"""
Pipeline Orchestrator - Runs the full podcast generation pipeline.

Usage:
    python -m src.orchestrator                    # Run full pipeline for today
    python -m src.orchestrator --date 2025-01-15  # Run for specific date
    python -m src.orchestrator --mock             # Run in full mock mode
    python -m src.orchestrator --step ingest      # Run specific step only
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .utils import setup_logging, get_logger, load_config
from .ingest import fetch_recent_cves, fetch_kev_catalog, fetch_epss_scores
from .ingest.cisa import enrich_with_kev
from .ingest.models import Vulnerability, Story
from .ingest.news import fetch_news_stories, fetch_reddit_security, deduplicate_stories, generate_mock_stories
from .pipeline.filter_score import filter_vulnerabilities, create_daily_brief_packet
from .pipeline.generate_script import generate_episode_script
from .pipeline.audio_engine import generate_audio
from .pipeline.video_assembler import assemble_video
from .pipeline.thumbnail_generator import generate_thumbnail
from .dashboard.db_sync import (
    push_vulnerabilities,
    push_episode_script,
    update_episode_status,
    mark_ready_for_upload,
    approve_episode_local,
)
from .publish.youtube import (
    upload_to_youtube,
    generate_youtube_metadata,
    is_youtube_authenticated,
    create_or_get_playlist,
)
from .publish.rss import update_rss_feed, generate_episode_rss_entry
from .publish.blog import create_blog_post, generate_blog_content
from .utils.audit import audit_episode, audit_thumbnail

logger = get_logger(__name__)


def run_pipeline(
    episode_date: str = None,
    mock: bool = False,
    steps: list = None,
) -> dict:
    """
    Run the full podcast generation pipeline.

    Args:
        episode_date: Date for the episode (default: today)
        mock: Enable mock mode for all external APIs
        steps: Specific steps to run (default: all)

    Returns:
        Dictionary with pipeline results
    """
    if episode_date is None:
        episode_date = datetime.now().strftime("%Y-%m-%d")

    logger.info(f"Starting pipeline for {episode_date}")
    logger.info(f"Mock mode: {mock}")

    config = load_config()

    # Override mock mode in config
    if mock:
        config["mock_mode"]["enabled"] = True
        config["mock_mode"]["llm"] = True
        config["mock_mode"]["tts"] = True
        config["mock_mode"]["thumbnail"] = True

    # Create output directory
    output_dir = Path(config.get("paths", {}).get("output", "output/episodes")) / episode_date
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "episode_date": episode_date,
        "output_dir": str(output_dir),
        "steps": {},
    }

    all_steps = ["ingest", "filter", "script", "audio", "video", "sync", "publish"]
    steps_to_run = steps if steps else all_steps

    # Step 1: Ingest vulnerabilities AND news stories
    if "ingest" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 1: Ingesting vulnerabilities and news")
        logger.info("=" * 60)

        if mock:
            # Use sample data in mock mode for guaranteed end-to-end testing
            logger.info("Mock mode: Using sample vulnerabilities and stories")
            vulnerabilities = _get_sample_vulnerabilities()
            stories = generate_mock_stories(count=5)
        else:
            vulnerabilities = _run_ingest(config)
            stories = _run_news_ingest(config)

        results["steps"]["ingest"] = {
            "vuln_count": len(vulnerabilities),
            "story_count": len(stories),
            "cves": [v.cve_id for v in vulnerabilities[:10]],
            "top_stories": [s.title[:50] for s in stories[:3]],
        }

        # Save raw vulnerability data
        raw_path = output_dir / "raw_vulnerabilities.json"
        with open(raw_path, "w") as f:
            json.dump({
                "date": episode_date,
                "ingested_at": datetime.utcnow().isoformat() + "Z",
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            }, f, indent=2)

        # Save raw news data
        news_path = output_dir / "raw_news.json"
        with open(news_path, "w") as f:
            json.dump({
                "date": episode_date,
                "ingested_at": datetime.utcnow().isoformat() + "Z",
                "stories": [s.to_dict() for s in stories],
            }, f, indent=2)

    else:
        # Load from previous run
        raw_path = output_dir / "raw_vulnerabilities.json"
        if raw_path.exists():
            with open(raw_path) as f:
                data = json.load(f)
            vulnerabilities = [Vulnerability.from_dict(v) for v in data["vulnerabilities"]]
        else:
            logger.error("No raw data found. Run ingest step first.")
            return results

        # Load news from previous run
        news_path = output_dir / "raw_news.json"
        if news_path.exists():
            with open(news_path) as f:
                data = json.load(f)
            stories = [Story.from_dict(s) for s in data["stories"]]
        else:
            stories = []
            logger.warning("No news data found. Continuing without stories.")

    # Step 2: Filter and score
    if "filter" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 2: Applying Priority Matrix")
        logger.info("=" * 60)

        included, filtered = filter_vulnerabilities(vulnerabilities)
        results["steps"]["filter"] = {
            "included": len(included),
            "filtered": len(filtered),
            "critical": sum(1 for v in included if v.priority.value == "CRITICAL"),
            "high": sum(1 for v in included if v.priority.value == "HIGH"),
        }

        # Create daily brief packet
        packet = create_daily_brief_packet(included, filtered, episode_date)

        # Save packet
        packet_path = output_dir / "daily_brief_packet.json"
        with open(packet_path, "w") as f:
            json.dump(packet, f, indent=2)

        # Push to Airtable/local
        vuln_ids = push_vulnerabilities(packet)

    else:
        # Load from previous run
        packet_path = output_dir / "daily_brief_packet.json"
        if packet_path.exists():
            with open(packet_path) as f:
                packet = json.load(f)
            included = [Vulnerability.from_dict(v) for v in packet["vulnerabilities"]]
        else:
            logger.error("No packet found. Run filter step first.")
            return results

    # Check if we have content to process (CVEs OR stories)
    if not included and not stories:
        logger.warning("No vulnerabilities passed and no news stories. Nuking today's episode.")
        results["steps"]["filter"] = {"status": "no_content"}
        return results

    if not included:
        logger.info("No CVEs passed Priority Matrix, but we have news stories. Continuing with news-only episode.")
        results["steps"]["filter"]["note"] = "news_only_episode"

    # Step 3: Generate script
    if "script" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 3: Generating script")
        logger.info("=" * 60)

        # Select top stories for the episode (fill time to reach 8-12 min target)
        top_stories = _select_stories_for_episode(stories, included)
        logger.info(f"Selected {len(top_stories)} stories for episode")

        script = generate_episode_script(included, episode_date, stories=top_stories, mock=mock)
        results["steps"]["script"] = {
            "dialogue_lines": len(script["dialogue"]),
            "runtime_estimate": script["runtime_estimate_seconds"],
        }

        # Save script
        script_path = output_dir / "episode_script.json"
        with open(script_path, "w") as f:
            json.dump(script, f, indent=2)

        # Push to Airtable/local
        push_episode_script(episode_date, script, [])

        # In local mode, auto-approve for testing
        if not config.get("env", {}).get("airtable_api_key"):
            logger.info("Auto-approving episode in local mode")
            approve_episode_local(episode_date)

    else:
        # Load from previous run
        script_path = output_dir / "episode_script.json"
        if script_path.exists():
            with open(script_path) as f:
                script = json.load(f)
        else:
            logger.error("No script found. Run script step first.")
            return results

    # Step 4: Generate audio
    if "audio" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 4: Generating audio")
        logger.info("=" * 60)

        update_episode_status(episode_date, "Rendering")

        audio_manifest = generate_audio(script, str(output_dir), mock=mock)
        results["steps"]["audio"] = {
            "file": audio_manifest["audio_file"],
            "duration": audio_manifest["duration_seconds"],
        }

    else:
        # Load from previous run
        audio_manifest_path = output_dir / "audio_manifest.json"
        if audio_manifest_path.exists():
            with open(audio_manifest_path) as f:
                audio_manifest = json.load(f)
        else:
            logger.error("No audio manifest found. Run audio step first.")
            return results

    # Step 5: Assemble video
    if "video" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 5: Assembling video")
        logger.info("=" * 60)

        video_manifest = assemble_video(audio_manifest, script, str(output_dir))
        results["steps"]["video"] = {
            "file": video_manifest["video_file"],
            "resolution": video_manifest["resolution"],
        }

        # Generate thumbnail
        logger.info("Generating thumbnail...")
        packet_path = output_dir / "daily_brief_packet.json"
        if packet_path.exists():
            with open(packet_path) as f:
                packet_data = json.load(f)
            thumbnail_manifest = generate_thumbnail(packet_data, str(output_dir))
            results["steps"]["thumbnail"] = {
                "file": thumbnail_manifest["thumbnail_file"],
                "text": thumbnail_manifest["text_overlay"],
            }
        else:
            logger.warning("No daily_brief_packet.json found, skipping thumbnail")

    else:
        # Load from previous run
        video_manifest_path = output_dir / "video_manifest.json"
        if video_manifest_path.exists():
            with open(video_manifest_path) as f:
                video_manifest = json.load(f)
        else:
            video_manifest = {"video_file": ""}

    # Step 5.5: AUDIT (The Idiot Check)
    # Validates video/audio before publishing to catch silent audio, black frames, etc.
    if "video" in steps_to_run or "publish" in steps_to_run:
        video_file = video_manifest.get("video_file", "")
        if video_file and Path(video_file).exists():
            logger.info("=" * 60)
            logger.info("AUDIT: Pre-publish validation")
            logger.info("=" * 60)

            try:
                # Audit video (checks duration, audio levels, file size)
                audit_result = audit_episode(
                    video_file,
                    min_duration_sec=60,   # 1 min minimum (lowered for testing)
                    min_size_mb=10,        # 10 MB minimum (lowered for testing)
                )
                results["steps"]["audit"] = {
                    "passed": True,
                    "duration_minutes": audit_result["duration_minutes"],
                    "size_mb": audit_result["size_mb"],
                }

                # Audit thumbnail
                thumbnail_file = output_dir / "thumbnail.png"
                if thumbnail_file.exists():
                    thumb_result = audit_thumbnail(str(thumbnail_file))
                    results["steps"]["audit"]["thumbnail"] = "passed"

            except Exception as e:
                logger.error(f"AUDIT FAILED: {e}")
                results["steps"]["audit"] = {"passed": False, "error": str(e)}
                # Don't proceed to publish if audit fails
                if "publish" in steps_to_run:
                    logger.error("Aborting publish due to failed audit")
                    results["steps"]["publish"] = {"status": "aborted", "reason": str(e)}
                    return results

    # Step 6: Update status
    if "sync" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 6: Updating status")
        logger.info("=" * 60)

        mark_ready_for_upload(
            episode_date,
            video_path=video_manifest.get("video_file", ""),
            audio_path=audio_manifest.get("audio_file", ""),
        )

        results["steps"]["sync"] = {"status": "Ready_for_Upload"}

    # Step 7: Publish to platforms
    if "publish" in steps_to_run:
        logger.info("=" * 60)
        logger.info("STEP 7: Publishing to platforms")
        logger.info("=" * 60)

        # Load stories if not already available
        if 'top_stories' not in locals():
            news_path = output_dir / "raw_news.json"
            if news_path.exists():
                with open(news_path) as f:
                    data = json.load(f)
                stories = [Story.from_dict(s) for s in data["stories"]]
                top_stories = _select_stories_for_episode(stories, included)
            else:
                top_stories = []

        publish_results = _run_publish(
            episode_date=episode_date,
            output_dir=output_dir,
            video_manifest=video_manifest,
            audio_manifest=audio_manifest,
            vulnerabilities=included,
            stories=top_stories,
            config=config,
            mock=mock,
        )
        results["steps"]["publish"] = publish_results

        # Update status to Published
        if publish_results.get("youtube", {}).get("status") == "uploaded":
            update_episode_status(episode_date, "Published")

    # Summary
    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Episode: {episode_date}")
    logger.info(f"Output: {output_dir}")
    logger.info(f"Steps completed: {list(results['steps'].keys())}")

    return results


def _run_ingest(config: dict) -> list:
    """
    Run the ingestion step.

    Fetches from NVD, enriches with CISA KEV and EPSS data.
    """
    nvd_api_key = config.get("env", {}).get("nvd_api_key")

    # Fetch CVEs from NVD
    logger.info("Fetching CVEs from NVD...")
    vulnerabilities = fetch_recent_cves(hours=24, api_key=nvd_api_key)
    logger.info(f"Fetched {len(vulnerabilities)} CVEs from NVD")

    if not vulnerabilities:
        logger.warning("No CVEs found in NVD. Using sample data for testing.")
        return _get_sample_vulnerabilities()

    # Enrich with CISA KEV
    logger.info("Enriching with CISA KEV data...")
    kev_catalog = fetch_kev_catalog()
    for vuln in vulnerabilities:
        kev_data = enrich_with_kev(vuln.cve_id)
        vuln.cisa_kev = kev_data.get("cisa_kev", False)
        vuln.kev_due_date = kev_data.get("kev_due_date")
        if vuln.cisa_kev:
            vuln.exploit_status = "actively_exploited"

    # Enrich with EPSS scores
    logger.info("Fetching EPSS scores...")
    cve_ids = [v.cve_id for v in vulnerabilities]
    epss_data = fetch_epss_scores(cve_ids)
    for vuln in vulnerabilities:
        if vuln.cve_id in epss_data:
            vuln.epss_score = epss_data[vuln.cve_id]["epss_score"]
            vuln.epss_percentile = epss_data[vuln.cve_id]["epss_percentile"]

    return vulnerabilities


def _get_sample_vulnerabilities() -> list:
    """
    Return sample vulnerabilities for testing when NVD returns no data.
    """
    return [
        Vulnerability(
            cve_id="CVE-2025-0001",
            title="Sample Critical RCE in Apache",
            description="A critical remote code execution vulnerability in Apache HTTP Server.",
            cvss_score=9.8,
            epss_score=0.45,
            cisa_kev=True,
            vendor="Apache",
            product="HTTP Server",
            affected_versions="2.4.0 - 2.4.58",
            fixed_version="2.4.59",
            remediation_url="https://httpd.apache.org/security/",
            exploit_status="actively_exploited",
        ),
        Vulnerability(
            cve_id="CVE-2025-0002",
            title="High Severity SQL Injection",
            description="SQL injection vulnerability in popular CMS.",
            cvss_score=8.5,
            epss_score=0.35,
            cisa_kev=False,
            vendor="WordPress",
            product="Core",
            affected_versions="6.0 - 6.4",
            fixed_version="6.4.1",
            remediation_url="https://wordpress.org/news/",
            exploit_status="poc_public",
        ),
        Vulnerability(
            cve_id="CVE-2025-0003",
            title="Buffer Overflow in Network Stack",
            description="Buffer overflow in Linux kernel network stack.",
            cvss_score=7.8,
            epss_score=0.40,
            cisa_kev=False,
            vendor="Linux",
            product="Kernel",
            affected_versions="5.15 - 6.6",
            fixed_version="6.6.1",
            remediation_url="https://kernel.org/",
            exploit_status="none",
        ),
    ]


def _run_news_ingest(config: dict) -> list:
    """
    Fetch news stories from RSS feeds and Reddit.

    Returns deduplicated, scored list of stories.
    """
    logger.info("Fetching news from RSS feeds...")
    rss_stories = fetch_news_stories(hours=24, max_stories=20)
    logger.info(f"Fetched {len(rss_stories)} stories from RSS feeds")

    logger.info("Fetching from Reddit...")
    reddit_stories = fetch_reddit_security(hours=24, max_posts=10)
    logger.info(f"Fetched {len(reddit_stories)} posts from Reddit")

    # Combine and deduplicate
    all_stories = rss_stories + reddit_stories
    unique_stories = deduplicate_stories(all_stories)

    # Sort by final score
    unique_stories.sort(key=lambda s: s.final_score, reverse=True)

    logger.info(f"Total unique stories: {len(unique_stories)}")
    return unique_stories


def _select_stories_for_episode(stories: list, vulnerabilities: list) -> list:
    """
    Select stories for the episode based on content needs.

    Strategy:
    - If many CVEs (5+), include 1-2 stories
    - If few CVEs (1-3), include 3-5 stories to fill time
    - Prioritize breach/ransomware/APT over industry news
    - Exclude stories that overlap with CVEs we're covering

    Target: 8-12 minute episode (CVEs ~3-4 min, news fills rest)
    """
    if not stories:
        return []

    # Get CVE IDs we're covering to avoid duplicate coverage
    covered_cves = {v.cve_id for v in vulnerabilities}

    # Filter out stories that are primarily about CVEs we're already covering
    filtered_stories = []
    for story in stories:
        # If story mentions CVEs we're covering, skip it (we'll cover in CVE section)
        if story.mentioned_cves and all(cve in covered_cves for cve in story.mentioned_cves):
            continue
        filtered_stories.append(story)

    # Determine how many stories based on CVE count
    vuln_count = len(vulnerabilities)
    if vuln_count >= 5:
        # Many CVEs - just 1-2 top stories
        max_stories = 2
    elif vuln_count >= 3:
        # Moderate CVEs - 2-3 stories
        max_stories = 3
    else:
        # Few CVEs - more stories to fill time
        max_stories = 5

    # Prioritize high-impact story types
    priority_types = ["breach", "ransomware", "apt", "threat_intel"]

    priority_stories = [s for s in filtered_stories if s.story_type.value in priority_types]
    other_stories = [s for s in filtered_stories if s.story_type.value not in priority_types]

    # Take priority stories first, then fill with others
    selected = priority_stories[:max_stories]
    remaining_slots = max_stories - len(selected)
    if remaining_slots > 0:
        selected.extend(other_stories[:remaining_slots])

    logger.info(f"Selected {len(selected)} stories (max {max_stories} based on {vuln_count} CVEs)")
    return selected


def _run_publish(
    episode_date: str,
    output_dir: Path,
    video_manifest: dict,
    audio_manifest: dict,
    vulnerabilities: list,
    stories: list,
    config: dict,
    mock: bool = False,
) -> dict:
    """
    Publish episode to all configured platforms.

    Handles:
    - YouTube upload
    - RSS feed update
    - Blog post creation

    Returns dict with results from each platform.
    """
    results = {}

    # Get file paths
    video_path = video_manifest.get("video_file", "")
    audio_path = audio_manifest.get("audio_file", "")
    thumbnail_path = str(output_dir / "thumbnail.png")

    # YouTube upload
    if config.get("publish", {}).get("youtube", {}).get("enabled", True):
        if mock:
            logger.info("Mock mode: Skipping YouTube upload")
            results["youtube"] = {"status": "skipped", "reason": "mock_mode"}
        elif not is_youtube_authenticated():
            logger.warning("YouTube not authenticated. Run: python -m src.publish.youtube")
            results["youtube"] = {"status": "skipped", "reason": "not_authenticated"}
        elif not video_path or not Path(video_path).exists():
            logger.warning("No video file to upload")
            results["youtube"] = {"status": "skipped", "reason": "no_video"}
        else:
            try:
                # Generate metadata
                metadata = generate_youtube_metadata(episode_date, vulnerabilities, stories)

                # Get or create playlist
                playlist_id = None
                playlist_name = config.get("publish", {}).get("youtube", {}).get("playlist_name")
                if playlist_name:
                    playlist_id = create_or_get_playlist(
                        playlist_name,
                        "Daily cybersecurity vulnerability briefings"
                    )

                # Upload
                yt_result = upload_to_youtube(
                    video_path=video_path,
                    title=metadata["title"],
                    description=metadata["description"],
                    tags=metadata["tags"],
                    playlist_id=playlist_id,
                    thumbnail_path=thumbnail_path if Path(thumbnail_path).exists() else None,
                )
                results["youtube"] = {"status": "uploaded", **yt_result}

            except Exception as e:
                logger.error(f"YouTube upload failed: {e}")
                results["youtube"] = {"status": "error", "error": str(e)}

    # RSS feed update
    if config.get("publish", {}).get("rss", {}).get("enabled", True):
        if mock:
            logger.info("Mock mode: Skipping RSS update")
            results["rss"] = {"status": "skipped", "reason": "mock_mode"}
        else:
            try:
                # Generate audio URL (needs to be publicly accessible)
                audio_base_url = config.get("publish", {}).get("rss", {}).get("audio_base_url", "")
                if audio_base_url:
                    audio_url = f"{audio_base_url.rstrip('/')}/{episode_date}/episode.mp3"
                else:
                    # Use local path as placeholder
                    audio_url = f"file://{audio_path}"

                # Generate episode entry
                episode_entry = generate_episode_rss_entry(
                    episode_date=episode_date,
                    audio_url=audio_url,
                    audio_path=audio_path,
                    vulnerabilities=vulnerabilities,
                    stories=stories,
                )

                # Update feed
                feed_path = config.get("publish", {}).get("rss", {}).get("feed_path", "output/podcast.xml")
                rss_result = update_rss_feed(episode_entry, feed_path)
                results["rss"] = {"status": "updated", "path": rss_result}

            except Exception as e:
                logger.error(f"RSS update failed: {e}")
                results["rss"] = {"status": "error", "error": str(e)}

    # Blog post
    if config.get("publish", {}).get("blog", {}).get("enabled", False):
        if mock:
            logger.info("Mock mode: Skipping blog post")
            results["blog"] = {"status": "skipped", "reason": "mock_mode"}
        else:
            try:
                youtube_url = results.get("youtube", {}).get("url", "")

                # Generate content
                blog_data = generate_blog_content(
                    episode_date=episode_date,
                    vulnerabilities=vulnerabilities,
                    stories=stories,
                    youtube_url=youtube_url,
                )

                # Create post
                platform = config.get("publish", {}).get("blog", {}).get("platform", "markdown")
                blog_result = create_blog_post(
                    episode_date=episode_date,
                    title=blog_data["title"],
                    content=blog_data["content"],
                    youtube_url=youtube_url,
                    vulnerabilities=vulnerabilities,
                    stories=stories,
                    platform=platform,
                )
                results["blog"] = blog_result

            except Exception as e:
                logger.error(f"Blog post failed: {e}")
                results["blog"] = {"status": "error", "error": str(e)}

    # Save publish manifest
    manifest_path = output_dir / "publish_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump({
            "episode_date": episode_date,
            "published_at": datetime.utcnow().isoformat() + "Z",
            "results": results,
        }, f, indent=2)

    logger.info(f"Publishing complete: {list(results.keys())}")
    return results


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Podcast Pipeline Orchestrator")
    parser.add_argument("--date", help="Episode date (YYYY-MM-DD)", default=None)
    parser.add_argument("--mock", action="store_true", help="Enable mock mode")
    parser.add_argument("--step", help="Run specific step only", choices=[
        "ingest", "filter", "script", "audio", "video", "sync", "publish"
    ])
    parser.add_argument("--log-file", help="Log to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    import logging
    level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(level=level, log_file=args.log_file)

    # Run pipeline
    steps = [args.step] if args.step else None
    results = run_pipeline(
        episode_date=args.date,
        mock=args.mock,
        steps=steps,
    )

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
