#!/usr/bin/env python3
"""
ThreatCluster Interactive CLI
A comprehensive command-line interface for monitoring and controlling the threat clustering pipeline
"""

import sys
import os

# Set offline mode for HuggingFace to avoid rate limiting
os.environ['HF_HUB_OFFLINE'] = '1'
import time
import argparse
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import signal
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt, Confirm
from rich import box
import logging

# Load .env file if available
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cluster.database_connection import db_manager
from cluster.core import create_pipeline

# Initialize Rich console
console = Console()

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    console.print("\n[yellow]⚠️  Shutdown requested. Finishing current operation...[/yellow]")


def print_banner():
    """Print the ThreatCluster banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗             ║
║  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝             ║
║     ██║   ███████║██████╔╝█████╗  ███████║   ██║                ║
║     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║                ║
║     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║                ║
║     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝                ║
║                                                                  ║
║   ██████╗██╗     ██╗   ██╗███████╗████████╗███████╗██████╗      ║
║  ██╔════╝██║     ██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗     ║
║  ██║     ██║     ██║   ██║███████╗   ██║   █████╗  ██████╔╝     ║
║  ██║     ██║     ██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗     ║
║  ╚██████╗███████╗╚██████╔╝███████║   ██║   ███████╗██║  ██║     ║
║   ╚═════╝╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝     ║
║                                                                  ║
║         Cybersecurity News Aggregation & Clustering System       ║
╚══════════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bright_cyan")


def create_status_table(stats: Dict[str, Any]) -> Table:
    """Create a status table with current statistics"""
    table = Table(title="Current Status", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Last Run", stats.get('last_run', 'Never'))
    table.add_row("Articles Fetched", str(stats.get('articles_fetched', 0)))
    table.add_row("Security Relevant", str(stats.get('security_relevant', 0)))
    table.add_row("Active Clusters", str(stats.get('active_clusters', 0)))
    table.add_row("Entities Tracked", str(stats.get('total_entities', 0)))
    table.add_row("New Threats (24h)", str(stats.get('new_threats_24h', 0)))
    
    return table


def run_stage_with_progress(stage_name: str, stage_func, *args, **kwargs):
    """Run a pipeline stage with progress indicator"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(f"[cyan]{stage_name}...", total=None)
        
        try:
            result = stage_func(*args, **kwargs)
            progress.update(task, completed=100)
            return result
        except Exception as e:
            console.print(f"[red]✗ {stage_name} failed: {e}[/red]")
            raise


def display_feed_results(results: Dict):
    """Display feed collection results"""
    table = Table(title="Feed Collection Results", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Total Fetched", str(results.get('total_fetched', 0)))
    table.add_row("Security Relevant", str(results.get('security_relevant', 0)))
    table.add_row("Filtered Out", str(results.get('filtered_out', 0)))
    table.add_row("Saved to Database", str(results.get('saved', 0)))
    
    console.print(table)


def display_cluster_results(results: Dict):
    """Display clustering results"""
    table = Table(title="Clustering Results", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Clusters Created", str(results.get('clusters_created', 0)))
    table.add_row("Articles Clustered", str(results.get('articles_clustered', 0)))
    table.add_row("Articles Assigned to Existing", str(results.get('articles_assigned', 0)))
    
    console.print(table)


def display_entity_results(results: Dict):
    """Display entity refresh results"""
    table = Table(title="Entity Refresh Results", box=box.ROUNDED)
    
    table.add_column("Operation", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Entities Cleaned", str(results.get('cleaned', 0)))
    
    discovered = results.get('discovered', {})
    for entity_type, count in discovered.items():
        table.add_row(f"Discovered {entity_type}", str(count))
    
    promoted = results.get('promoted', {})
    for entity_type, entities in promoted.items():
        table.add_row(f"Promoted {entity_type}", str(len(entities)))
    
    console.print(table)


def display_ranking_results(results: Dict):
    """Display ranking results"""
    table = Table(title="Ranking Results", box=box.ROUNDED)
    
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Clusters Ranked", str(results.get('clusters_ranked', 0)))
    table.add_row("Articles Ranked", str(results.get('articles_ranked', 0)))
    
    console.print(table)


def get_system_stats(session) -> Dict[str, Any]:
    """Get current system statistics"""
    from sqlalchemy import text
    
    stats = {}
    
    # Last run time
    try:
        result = session.execute(text("""
            SELECT completed_at 
            FROM cluster.processing_runs 
            WHERE status = 'completed' 
            ORDER BY completed_at DESC 
            LIMIT 1
        """)).fetchone()
        
        if result and result.completed_at:
            stats['last_run'] = result.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            stats['last_run'] = "Never"
    except:
        stats['last_run'] = "Unknown"
    
    # Article stats
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as total,
                   COUNT(CASE WHEN processed_at IS NOT NULL THEN 1 END) as processed
            FROM cluster.articles
            WHERE fetched_at > NOW() - INTERVAL '24 hours'
        """)).fetchone()
        
        stats['articles_fetched'] = result.total if result else 0
        stats['security_relevant'] = result.processed if result else 0
    except:
        stats['articles_fetched'] = 0
        stats['security_relevant'] = 0
    
    # Active clusters
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as count
            FROM cluster.clusters
            WHERE is_active = TRUE
        """)).fetchone()
        
        stats['active_clusters'] = result.count if result else 0
    except:
        stats['active_clusters'] = 0
    
    # Total entities
    try:
        result = session.execute(text("""
            SELECT COUNT(*) as count
            FROM cluster.entities
            WHERE is_predefined = TRUE OR occurrence_count > 5
        """)).fetchone()
        
        stats['total_entities'] = result.count if result else 0
    except:
        stats['total_entities'] = 0
    
    # New threats in last 24h
    try:
        result = session.execute(text("""
            SELECT COUNT(DISTINCT e.value) as count
            FROM cluster.entities e
            JOIN cluster.article_entities ae ON e.id = ae.entity_id
            JOIN cluster.articles a ON ae.article_id = a.id
            WHERE e.entity_type IN ('ransomware_group', 'apt_group', 'malware_family')
            AND a.fetched_at > NOW() - INTERVAL '24 hours'
        """)).fetchone()
        
        stats['new_threats_24h'] = result.count if result else 0
    except:
        stats['new_threats_24h'] = 0
    
    return stats


def interactive_mode():
    """Run in interactive mode with menu"""
    print_banner()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    with db_manager.session() as session:
        pipeline = create_pipeline(session)
        
        while not shutdown_requested:
            # Get current stats
            stats = get_system_stats(session)
            
            # Display status
            console.print("\n")
            console.print(create_status_table(stats))
            
            # Menu
            console.print("\n[bold cyan]Available Actions:[/bold cyan]")
            console.print("1. Run Full Pipeline")
            console.print("2. Collect Feeds Only")
            console.print("3. Cluster Articles Only")
            console.print("4. Refresh Entities Only")
            console.print("5. Update Rankings Only")
            console.print("6. View Recent Clusters")
            console.print("7. View All Clusters")
            console.print("8. View Top Threats")
            console.print("9. Ingest IOCs from Threat Feeds")
            console.print("10. Import Threat Actors from MISP Galaxy")
            console.print("11. Import MITRE ATT&CK Techniques")
            console.print("12. Re-extract Entities (without re-clustering)")
            console.print("13. Continuous Mode")
            console.print("14. Re-cluster Everything")
            console.print("15. Fix Entity Occurrence Counts")
            console.print("16. Clean Up Duplicate Clusters")
            console.print("17. Undo Last Clustering Run")
            console.print("18. Exit")
            
            choice = Prompt.ask("\n[bold]Select action[/bold]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"])
            
            try:
                if choice == "1":
                    # Full pipeline
                    console.print("\n[bold cyan]Running Full Pipeline[/bold cyan]")
                    
                    # Feed collection
                    console.print("\n[yellow]Stage 1/4: Collecting Feeds[/yellow]")
                    try:
                        feed_results = run_stage_with_progress("Feed Collection", pipeline.collect_feeds)
                        display_feed_results(feed_results)
                    except Exception as e:
                        console.print(f"[red]Feed collection error: {e}[/red]")
                        import traceback
                        traceback.print_exc()
                        feed_results = {'status': 'error'}
                    
                    if shutdown_requested:
                        break
                    
                    # Clustering
                    console.print("\n[yellow]Stage 2/4: Clustering Articles[/yellow]")
                    cluster_results = run_stage_with_progress("Article Clustering", pipeline.cluster_articles)
                    display_cluster_results(cluster_results)
                    
                    if shutdown_requested:
                        break
                    
                    # Entity refresh
                    console.print("\n[yellow]Stage 3/4: Refreshing Entities[/yellow]")
                    entity_results = run_stage_with_progress("Entity Refresh", pipeline.refresh_entities)
                    display_entity_results(entity_results)
                    
                    if shutdown_requested:
                        break
                    
                    # Ranking
                    console.print("\n[yellow]Stage 4/4: Updating Rankings[/yellow]")
                    ranking_results = run_stage_with_progress("Ranking Update", pipeline.update_rankings)
                    display_ranking_results(ranking_results)
                    
                    console.print("\n[green]✓ Pipeline completed successfully![/green]")
                
                elif choice == "2":
                    # Feeds only
                    console.print("\n[bold cyan]Collecting Feeds[/bold cyan]")
                    results = run_stage_with_progress("Feed Collection", pipeline.collect_feeds)
                    display_feed_results(results)
                
                elif choice == "3":
                    # Clustering only
                    days = Prompt.ask("Days to look back", default="14")
                    console.print(f"\n[bold cyan]Clustering Articles (last {days} days)[/bold cyan]")
                    results = run_stage_with_progress("Article Clustering", pipeline.cluster_articles, int(days))
                    display_cluster_results(results)
                
                elif choice == "4":
                    # Entity refresh only
                    days = Prompt.ask("Days to look back", default="30")
                    console.print(f"\n[bold cyan]Refreshing Entities (last {days} days)[/bold cyan]")
                    results = run_stage_with_progress("Entity Refresh", pipeline.refresh_entities, int(days))
                    display_entity_results(results)
                
                elif choice == "5":
                    # Ranking only
                    console.print("\n[bold cyan]Updating Rankings[/bold cyan]")
                    results = run_stage_with_progress("Ranking Update", pipeline.update_rankings)
                    display_ranking_results(results)
                
                elif choice == "6":
                    # View recent clusters
                    view_recent_clusters(session)
                
                elif choice == "7":
                    # View all clusters
                    view_all_clusters(session)
                
                elif choice == "8":
                    # View top threats
                    view_top_threats(session)
                
                elif choice == "9":
                    # Ingest IOCs
                    console.print("\n[bold cyan]Ingesting IOCs from Threat Feeds[/bold cyan]")
                    run_ioc_ingestion(session)
                
                elif choice == "10":
                    # Import Threat Actors from MISP Galaxy
                    console.print("\n[bold cyan]Import Threat Actors from MISP Galaxy[/bold cyan]")
                    run_misp_galaxy_import(session)
                
                elif choice == "11":
                    # Import MITRE ATT&CK Techniques
                    console.print("\n[bold cyan]Import MITRE ATT&CK Techniques[/bold cyan]")
                    run_mitre_attack_import(session)
                
                elif choice == "12":
                    # Re-extract entities
                    console.print("\n[bold cyan]Re-extract Entities[/bold cyan]")
                    run_entity_reextraction(session, pipeline)
                
                elif choice == "13":
                    # Continuous mode
                    run_continuous_mode(pipeline)
                
                elif choice == "14":
                    # Re-cluster everything
                    run_full_recluster(session, pipeline)
                
                elif choice == "15":
                    # Fix entity occurrence counts
                    console.print("\n[bold cyan]Fix Entity Occurrence Counts[/bold cyan]")
                    run_fix_occurrence_counts(session)
                
                elif choice == "16":
                    # Clean up duplicate clusters
                    console.print("\n[bold cyan]Clean Up Duplicate Clusters[/bold cyan]")
                    run_cluster_cleanup(session)
                
                elif choice == "17":
                    # Undo last clustering run
                    console.print("\n[bold cyan]Undo Last Clustering Run[/bold cyan]")
                    run_undo_last_clustering(session)
                
                elif choice == "18":
                    # Exit
                    if Confirm.ask("\n[yellow]Are you sure you want to exit?[/yellow]"):
                        break
                
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                logging.error(f"Operation failed: {e}", exc_info=True)
            
            if not shutdown_requested:
                console.print("\n[dim]Press Enter to continue...[/dim]")
                input()
    
    console.print("\n[green]Goodbye![/green]")


def view_recent_clusters(session):
    """View recent high-ranking clusters"""
    from sqlalchemy import text
    
    console.print("\n[bold cyan]Recent High-Ranking Clusters[/bold cyan]\n")
    
    result = session.execute(text("""
        SELECT 
            c.id,
            c.ranking_score,
            COUNT(DISTINCT ca.article_id) as article_count,
            array_agg(DISTINCT a.title ORDER BY a.title) as titles,
            array_agg(DISTINCT e.value ORDER BY e.value) FILTER (WHERE e.entity_type IN ('ransomware_group', 'apt_group', 'malware_family')) as threats
        FROM cluster.clusters c
        JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
        JOIN cluster.articles a ON ca.article_id = a.id
        LEFT JOIN cluster.cluster_shared_entities cse ON c.id = cse.cluster_id
        LEFT JOIN cluster.entities e ON cse.entity_id = e.id
        WHERE c.is_active = TRUE
        AND c.updated_at > NOW() - INTERVAL '48 hours'
        GROUP BY c.id
        ORDER BY c.ranking_score DESC NULLS LAST
        LIMIT 10
    """)).fetchall()
    
    for idx, row in enumerate(result, 1):
        threats = [t for t in (row.threats or []) if t] or ["Unknown"]
        score = row.ranking_score or 0
        
        # Create panel for each cluster
        content = f"[bold]Score:[/bold] {score:.0f}\n"
        content += f"[bold]Articles:[/bold] {row.article_count}\n"
        content += f"[bold]Threats:[/bold] {', '.join(threats)}\n\n"
        content += "[bold]Titles:[/bold]\n"
        
        for title in row.titles[:3]:
            if title:
                content += f"• {title[:100]}{'...' if len(title) > 100 else ''}\n"
        
        panel = Panel(content, title=f"Cluster #{idx}", border_style="cyan")
        console.print(panel)


def view_all_clusters(session):
    """View all active clusters with pagination"""
    from sqlalchemy import text
    
    console.print("\n[bold cyan]All Active Clusters[/bold cyan]\n")
    
    # Get total count
    count_result = session.execute(text("""
        SELECT COUNT(*) as total
        FROM cluster.clusters
        WHERE is_active = TRUE
    """)).fetchone()
    
    total_clusters = count_result.total if count_result else 0
    
    if total_clusters == 0:
        console.print("[yellow]No active clusters found.[/yellow]")
        return
    
    console.print(f"[green]Total Active Clusters: {total_clusters}[/green]\n")
    
    # Pagination settings
    page_size = 10
    current_page = 1
    total_pages = (total_clusters + page_size - 1) // page_size
    
    while True:
        offset = (current_page - 1) * page_size
        
        # Fetch clusters for current page
        result = session.execute(text("""
            SELECT 
                c.id,
                c.cluster_uuid,
                c.ranking_score,
                c.created_at,
                c.updated_at,
                COUNT(DISTINCT ca.article_id) as article_count,
                array_agg(DISTINCT a.title ORDER BY a.title) as titles,
                array_agg(DISTINCT e.value ORDER BY e.value) FILTER (WHERE e.entity_type IN ('ransomware_group', 'apt_group', 'malware_family')) as threats,
                array_agg(DISTINCT e.value ORDER BY e.value) FILTER (WHERE e.entity_type = 'cve') as cves,
                array_agg(DISTINCT e.value ORDER BY e.value) FILTER (WHERE e.entity_type = 'company') as companies
            FROM cluster.clusters c
            JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
            JOIN cluster.articles a ON ca.article_id = a.id
            LEFT JOIN cluster.cluster_shared_entities cse ON c.id = cse.cluster_id
            LEFT JOIN cluster.entities e ON cse.entity_id = e.id
            WHERE c.is_active = TRUE
            GROUP BY c.id, c.cluster_uuid, c.ranking_score, c.created_at, c.updated_at
            ORDER BY c.created_at DESC
            LIMIT :limit OFFSET :offset
        """), {'limit': page_size, 'offset': offset}).fetchall()
        
        # Clear screen for better display
        console.clear()
        console.print(f"\n[bold cyan]All Active Clusters - Page {current_page}/{total_pages}[/bold cyan]\n")
        
        # Create table
        table = Table(box=box.ROUNDED, show_lines=True, width=None)
        table.add_column("ID", style="cyan", no_wrap=True, width=4)
        table.add_column("Created", style="blue", no_wrap=True)
        table.add_column("Articles", style="green", justify="center", width=8)
        table.add_column("Score", style="yellow", justify="right", width=6)
        table.add_column("Threats", style="red", width=25)
        table.add_column("CVEs", style="magenta", width=20)
        table.add_column("First Article Title", style="white", width=60)
        
        for row in result:
            # Format date
            created = row.created_at.strftime("%Y-%m-%d") if row.created_at else "Unknown"
            
            # Format threats
            threats = []
            if row.threats:
                threats = [t for t in row.threats if t][:3]  # Show max 3
            threat_str = ", ".join(threats) if threats else "-"
            if row.threats and len(row.threats) > 3:
                threat_str += f" (+{len(row.threats) - 3})"
            
            # Format CVEs
            cves = []
            if row.cves:
                cves = [c for c in row.cves if c][:2]  # Show max 2
            cve_str = ", ".join(cves) if cves else "-"
            if row.cves and len(row.cves) > 2:
                cve_str += f" (+{len(row.cves) - 2})"
            
            # Format score
            score_str = f"{row.ranking_score:.0f}" if row.ranking_score else "-"
            
            # Get first article title
            first_title = row.titles[0][:57] + "..." if row.titles and row.titles[0] and len(row.titles[0]) > 60 else (row.titles[0] if row.titles else "No title")
            
            table.add_row(
                str(row.id),
                created,
                str(row.article_count),
                score_str,
                threat_str,
                cve_str,
                first_title
            )
        
        console.print(table)
        
        # Pagination controls
        console.print(f"\n[dim]Page {current_page} of {total_pages} | Total clusters: {total_clusters}[/dim]")
        console.print("\n[bold]Navigation:[/bold] [n]ext page, [p]revious page, [g]o to page, [v]iew cluster details, [q]uit")
        
        nav_choice = Prompt.ask("Action", choices=["n", "p", "g", "v", "q"], default="n")
        
        if nav_choice == "n" and current_page < total_pages:
            current_page += 1
        elif nav_choice == "p" and current_page > 1:
            current_page -= 1
        elif nav_choice == "g":
            page_num = Prompt.ask(f"Go to page (1-{total_pages})", default=str(current_page))
            try:
                page_num = int(page_num)
                if 1 <= page_num <= total_pages:
                    current_page = page_num
                else:
                    console.print(f"[red]Invalid page number. Please enter a number between 1 and {total_pages}.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a number.[/red]")
        elif nav_choice == "v":
            cluster_id = Prompt.ask("Enter cluster ID to view details")
            try:
                cluster_id = int(cluster_id)
                view_cluster_details(session, cluster_id)
                console.print("\n[dim]Press Enter to continue...[/dim]")
                input()
            except ValueError:
                console.print("[red]Invalid cluster ID.[/red]")
        elif nav_choice == "q":
            break


def run_ioc_ingestion(session):
    """Run IOC ingestion from threat feeds"""
    import asyncio
    from rich.panel import Panel
    from core.ioc_ingester import IOCIngester
    
    console.print("\n[bold]IOC Feed Ingestion[/bold]\n")
    
    # Show available feeds
    ingester = IOCIngester(session)
    active_feeds = [f for f in ingester.feeds if f.get('active', True)]
    inactive_feeds = [f for f in ingester.feeds if not f.get('active', True)]
    
    console.print(f"[green]Active feeds:[/green] {len(active_feeds)}")
    console.print(f"[yellow]Inactive feeds:[/yellow] {len(inactive_feeds)}")
    
    console.print("\n[bold]Active Feeds:[/bold]")
    for feed in active_feeds:
        console.print(f"  • {feed['name']} ({feed['type']})")
    
    console.print("\nOptions:")
    console.print("1. Run all active IOC feeds")
    console.print("2. Select specific IOC feeds")
    console.print("3. View IOC feed details")
    console.print("4. Clean up old IOCs")
    console.print("5. Back to main menu")
    
    choice = Prompt.ask("\n[bold]Select option[/bold]", choices=["1", "2", "3", "4", "5"])
    
    if choice == "1":
        # Run all active feeds
        console.print("\n[yellow]Ingesting IOCs from all active feeds...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Ingesting IOCs...", total=None)
            
            # Run async ingestion
            stats = asyncio.run(ingester.ingest_all_feeds())
            
            progress.update(task, completed=100)
        
        # Display results
        table = Table(title="IOC Ingestion Results", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Feeds Processed", str(stats['feeds_processed']))
        table.add_row("IOCs Found", str(stats['iocs_found']))
        table.add_row("New IOCs Added", str(stats['iocs_added']))
        table.add_row("IOCs Updated", str(stats['iocs_updated']))
        table.add_row("Errors", str(stats['errors']))
        
        console.print("\n")
        console.print(table)
        
    elif choice == "2":
        # Select specific feeds
        console.print("\n[bold]Available Feeds:[/bold]")
        for idx, feed in enumerate(ingester.feeds, 1):
            status = "[green]Active[/green]" if feed.get('active', True) else "[red]Inactive[/red]"
            console.print(f"{idx}. {feed['name']} ({feed['type']}) - {status}")
        
        selected = Prompt.ask("\nEnter feed numbers to run (comma-separated)")
        feed_indices = [int(x.strip()) - 1 for x in selected.split(',')]
        
        # Temporarily activate only selected feeds
        original_states = {}
        for idx, feed in enumerate(ingester.feeds):
            original_states[idx] = feed.get('active', True)
            feed['active'] = idx in feed_indices
        
        # Run ingestion
        console.print("\n[yellow]Ingesting IOCs from selected feeds...[/yellow]")
        stats = asyncio.run(ingester.ingest_all_feeds())
        
        # Restore original states
        for idx, state in original_states.items():
            ingester.feeds[idx]['active'] = state
        
        # Display results
        console.print(f"\n[green]✓ Processed {stats['feeds_processed']} feeds[/green]")
        console.print(f"[green]✓ Added {stats['iocs_added']} new IOCs[/green]")
        
    elif choice == "3":
        # View feed details
        for feed in ingester.feeds:
            status = "[green]Active[/green]" if feed.get('active', True) else "[red]Inactive[/red]"
            panel = Panel(
                f"[bold]URL:[/bold] {feed['url']}\n"
                f"[bold]Type:[/bold] {feed['type']}\n"
                f"[bold]Format:[/bold] {feed.get('format', 'plain')}\n"
                f"[bold]Status:[/bold] {status}\n"
                f"[bold]Description:[/bold] {feed.get('description', 'N/A')}",
                title=feed['name'],
                border_style="blue"
            )
            console.print(panel)
            console.print()
    
    elif choice == "4":
        # Clean up old IOCs
        days = Prompt.ask("Remove IOCs not seen in feeds for how many days?", default="30")
        if Confirm.ask(f"\n[yellow]This will remove IOCs not seen in feeds for {days} days. Continue?[/yellow]"):
            deleted = ingester.cleanup_old_iocs(int(days))
            console.print(f"\n[green]✓ Removed {deleted} stale IOCs[/green]")


def run_misp_galaxy_import(session):
    """Import threat actors from MISP Galaxy"""
    import asyncio
    from core.misp_galaxy_importer import MISPGalaxyImporter
    
    console.print("\n[bold]MISP Galaxy Threat Actor Import[/bold]\n")
    
    importer = MISPGalaxyImporter(session)
    
    console.print("[bold]Available entity types:[/bold]")
    console.print("1. Ransomware Groups")
    console.print("2. APT Groups")
    console.print("3. Malware Families")
    console.print("4. Import All")
    console.print("5. Back to previous menu")
    
    choice = Prompt.ask("\n[bold]Select option[/bold]", choices=["1", "2", "3", "4", "5"])
    
    if choice == "5":
        return
    
    # Map choices to entity types
    entity_type_map = {
        "1": ["ransomware_group"],
        "2": ["apt_group"],
        "3": ["malware_family"],
        "4": ["ransomware_group", "apt_group", "malware_family"]
    }
    
    entity_types = entity_type_map[choice]
    entity_names = {
        "ransomware_group": "Ransomware Groups",
        "apt_group": "APT Groups",
        "malware_family": "Malware Families"
    }
    
    # Confirm import
    import_desc = ", ".join([entity_names[et] for et in entity_types])
    if not Confirm.ask(f"\n[yellow]Import {import_desc} from MISP Galaxy?[/yellow]"):
        return
    
    console.print(f"\n[yellow]Importing {import_desc}...[/yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Importing from MISP Galaxy...", total=None)
        
        # Run async import
        if choice == "4":
            results = asyncio.run(importer.import_all())
        else:
            results = asyncio.run(importer.import_specific(entity_types))
        
        progress.update(task, completed=100)
    
    # Display results
    console.print("\n[bold]Import Results:[/bold]\n")
    
    for entity_type, result in results['results'].items():
        table = Table(title=entity_names.get(entity_type, entity_type), box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        
        if result['status'] == 'success':
            table.add_row("Total in feed", str(result['total']))
            table.add_row("New entities imported", str(result['imported']))
            table.add_row("Existing entities updated", str(result['updated']))
            table.add_row("Errors", str(result['errors']))
        else:
            table.add_row("Status", f"[red]{result['status']}[/red]")
            table.add_row("Error", result.get('message', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Display total stats
    total_stats = results['total_stats']
    console.print("[bold]Total Statistics:[/bold]")
    console.print(f"• Total processed: {total_stats['total_processed']}")
    console.print(f"• New entities: {total_stats['new_entities']}")
    console.print(f"• Updated entities: {total_stats['updated_entities']}")
    console.print(f"• Errors: {total_stats['errors']}")
    
    console.print(f"\n[green]✓ MISP Galaxy import completed![/green]")


def run_mitre_attack_import(session):
    """Import MITRE ATT&CK techniques"""
    import asyncio
    from core.mitre_attack_importer import MITREAttackImporter
    
    console.print("\n[bold]MITRE ATT&CK Technique Import[/bold]\n")
    
    console.print("This will import all MITRE ATT&CK techniques including:")
    console.print("• Technique IDs (e.g., T1490)")
    console.print("• Technique names")
    console.print("• Metadata (tactics, platforms, descriptions)")
    console.print("• Both main techniques and sub-techniques")
    
    if not Confirm.ask("\n[yellow]Import MITRE ATT&CK techniques?[/yellow]"):
        return
    
    console.print("\n[yellow]Importing MITRE ATT&CK techniques...[/yellow]")
    
    importer = MITREAttackImporter(session)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Downloading and importing techniques...", total=None)
        
        # Run async import
        results = asyncio.run(importer.import_techniques())
        
        progress.update(task, completed=100)
    
    # Display results
    if results['status'] == 'success':
        stats = results['stats']
        
        table = Table(title="MITRE ATT&CK Import Results", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Total Processed", str(stats['total_processed']))
        table.add_row("New Techniques", str(stats['new_entities']))
        table.add_row("Updated Techniques", str(stats['updated_entities']))
        table.add_row("Skipped", str(stats['skipped']))
        table.add_row("Errors", str(stats['errors']))
        
        console.print("\n")
        console.print(table)
        
        # Get additional statistics
        technique_stats = importer.get_technique_stats()
        
        console.print("\n[bold]Technique Statistics:[/bold]")
        console.print(f"• Total techniques in database: {technique_stats['total_techniques']}")
        console.print(f"• Sub-techniques: {technique_stats['subtechniques']}")
        console.print(f"• Name aliases: {technique_stats['name_aliases']}")
        console.print(f"• Unique techniques: {technique_stats['unique_techniques']}")
        
        console.print(f"\n[green]✓ MITRE ATT&CK import completed successfully![/green]")
    else:
        console.print(f"\n[red]✗ Import failed: {results['message']}[/red]")


def run_cluster_cleanup(session):
    """Clean up duplicate clusters by merging similar ones"""
    from cluster.core.semantic_clusterer import SemanticClusterer
    
    console.print("\n[bold cyan]Duplicate Cluster Cleanup[/bold cyan]\n")
    console.print("This will find and merge clusters that are very similar to each other.")
    console.print("Similar clusters will be merged into the best one (highest score/newest).")
    
    # Ask for similarity threshold
    threshold = Prompt.ask("\nSimilarity threshold (0.0-1.0, higher = more strict)", default="0.8")
    threshold = float(threshold)
    
    if threshold < 0.0 or threshold > 1.0:
        console.print("[red]Invalid threshold. Must be between 0.0 and 1.0[/red]")
        return
    
    if not Confirm.ask(f"\n[yellow]Search for duplicate clusters with similarity >= {threshold}?[/yellow]"):
        return
    
    console.print(f"\n[yellow]Searching for duplicate clusters...[/yellow]")
    
    # Initialize clusterer
    clusterer = SemanticClusterer(session)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Cleaning up duplicates...", total=None)
        
        results = clusterer.cleanup_duplicate_clusters(threshold)
        
        progress.update(task, completed=100)
    
    # Display results
    console.print(f"\n[green]✓ Cleanup completed![/green]")
    console.print(f"\nStatistics:")
    console.print(f"• Clusters merged: {results['clusters_merged']}")
    console.print(f"• Clusters deactivated: {results['clusters_deactivated']}")
    
    if results['clusters_merged'] > 0:
        console.print(f"\n[bold]What happened:[/bold]")
        console.print(f"• Found {results['clusters_merged']} pairs of similar clusters")
        console.print(f"• Merged articles into the best cluster from each pair")
        console.print(f"• Deactivated {results['clusters_deactivated']} duplicate clusters")
        console.print(f"• No data was lost - articles were moved, not deleted")
    else:
        console.print(f"\n[yellow]No duplicate clusters found with similarity >= {threshold}[/yellow]")


def run_undo_last_clustering(session):
    """Undo the last clustering run by deactivating recent clusters"""
    from sqlalchemy import text
    
    console.print("\n[bold red]⚠️  WARNING: Undo Last Clustering Run[/bold red]")
    console.print("This will deactivate clusters created in the most recent clustering run.")
    console.print("Articles will become unclustered again but won't be deleted.")
    
    # Find the most recent clustering run
    try:
        recent_clusters = session.execute(text("""
            SELECT 
                DATE(c.created_at) as date,
                COUNT(*) as cluster_count,
                MIN(c.created_at) as first_created,
                MAX(c.created_at) as last_created,
                COUNT(DISTINCT ca.article_id) as article_count
            FROM cluster.clusters c
            JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
            WHERE c.is_active = true
            AND c.created_at > NOW() - INTERVAL '7 days'
            GROUP BY DATE(c.created_at)
            ORDER BY first_created DESC
            LIMIT 5
        """)).fetchall()
        
        if not recent_clusters:
            console.print("[yellow]No recent clustering runs found in the last 7 days.[/yellow]")
            return
        
        console.print("\n[bold]Recent clustering runs:[/bold]")
        table = Table(box=box.ROUNDED)
        table.add_column("Date", style="cyan")
        table.add_column("Clusters", style="green", justify="right")
        table.add_column("Articles", style="yellow", justify="right")
        table.add_column("Time Range", style="magenta")
        
        for i, run in enumerate(recent_clusters):
            time_range = f"{run.first_created.strftime('%H:%M')} - {run.last_created.strftime('%H:%M')}"
            table.add_row(
                run.date.strftime("%Y-%m-%d"),
                str(run.cluster_count),
                str(run.article_count),
                time_range
            )
        
        console.print(table)
        
        # Ask which date to undo
        console.print("\n[bold]Select which clustering run to undo:[/bold]")
        for i, run in enumerate(recent_clusters, 1):
            console.print(f"{i}. {run.date.strftime('%Y-%m-%d')} ({run.cluster_count} clusters, {run.article_count} articles)")
        
        choice = Prompt.ask("Select run to undo", choices=[str(i) for i in range(1, len(recent_clusters) + 1)])
        selected_run = recent_clusters[int(choice) - 1]
        
        # Get exact clusters from that date
        clusters_to_undo = session.execute(text("""
            SELECT 
                c.id,
                c.cluster_uuid,
                c.created_at,
                COUNT(DISTINCT ca.article_id) as article_count
            FROM cluster.clusters c
            JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
            WHERE c.is_active = true
            AND DATE(c.created_at) = :target_date
            GROUP BY c.id, c.cluster_uuid, c.created_at
            ORDER BY c.created_at
        """), {'target_date': selected_run.date}).fetchall()
        
        console.print(f"\n[bold]Clusters to be deactivated on {selected_run.date.strftime('%Y-%m-%d')}:[/bold]")
        console.print(f"• Total clusters: {len(clusters_to_undo)}")
        console.print(f"• Total articles: {sum(c.article_count for c in clusters_to_undo)}")
        console.print(f"• Time range: {selected_run.first_created.strftime('%H:%M')} - {selected_run.last_created.strftime('%H:%M')}")
        
        # Double confirmation
        if not Confirm.ask(f"\n[yellow]Are you sure you want to deactivate these {len(clusters_to_undo)} clusters?[/yellow]"):
            console.print("[green]Operation cancelled.[/green]")
            return
        
        # Final confirmation
        confirm_text = Prompt.ask(f"\nType 'UNDO {selected_run.date.strftime('%Y-%m-%d')}' to confirm")
        expected_text = f"UNDO {selected_run.date.strftime('%Y-%m-%d')}"
        
        if confirm_text != expected_text:
            console.print("[green]Operation cancelled - confirmation text didn't match.[/green]")
            return
        
        # Perform the undo
        console.print(f"\n[yellow]Deactivating clusters from {selected_run.date.strftime('%Y-%m-%d')}...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Deactivating clusters...", total=None)
            
            # Deactivate the clusters
            result = session.execute(text("""
                UPDATE cluster.clusters 
                SET is_active = false, updated_at = NOW()
                WHERE is_active = true
                AND DATE(created_at) = :target_date
            """), {'target_date': selected_run.date})
            
            deactivated_count = result.rowcount
            session.commit()
            
            progress.update(task, completed=100)
        
        console.print(f"\n[green]✓ Successfully deactivated {deactivated_count} clusters![/green]")
        console.print(f"\nWhat happened:")
        console.print(f"• Deactivated {deactivated_count} clusters from {selected_run.date.strftime('%Y-%m-%d')}")
        console.print(f"• Articles are now unclustered and available for new clustering")
        console.print(f"• No data was deleted - clusters are just marked as inactive")
        console.print(f"• You can re-run clustering to create new clusters")
        
        # Show current active cluster count
        active_count = session.execute(text("""
            SELECT COUNT(*) as count FROM cluster.clusters WHERE is_active = true
        """)).scalar()
        
        console.print(f"\nActive clusters remaining: {active_count}")
        
    except Exception as e:
        console.print(f"[red]Error during undo operation: {e}[/red]")
        session.rollback()
        import traceback
        traceback.print_exc()


def run_fix_occurrence_counts(session):
    """Fix entity occurrence counts based on actual article associations"""
    from cluster.core.entity_count_updater import update_entity_occurrence_counts, get_entity_occurrence_stats
    
    console.print("\n[bold cyan]Entity Occurrence Count Fixer[/bold cyan]\n")
    console.print("This will update occurrence counts for entities based on actual article associations.")
    console.print("Useful after importing entities or if counts are out of sync.")
    
    # Ask which entity type to fix
    entity_types = [
        ("All entity types", None),
        ("MITRE Techniques", "mitre_technique"),
        ("Ransomware Groups", "ransomware_group"),
        ("APT Groups", "apt_group"),
        ("Malware Families", "malware_family"),
        ("Companies", "company"),
        ("Industries", "industry"),
        ("Attack Types", "attack_type"),
        ("Platforms", "platform"),
        ("Other", "other")
    ]
    
    console.print("\n[bold]Select entity type to fix:[/bold]")
    for i, (name, _) in enumerate(entity_types, 1):
        console.print(f"{i}. {name}")
    
    choice = Prompt.ask("\nSelect option", choices=[str(i) for i in range(1, len(entity_types) + 1)])
    entity_type_name, entity_type = entity_types[int(choice) - 1]
    
    # Check current state
    console.print(f"\n[yellow]Checking current state of {entity_type_name}...[/yellow]")
    stats = get_entity_occurrence_stats(session, entity_type)
    
    if stats.get('integrity_issues'):
        console.print(f"\n[red]Found {len(stats['integrity_issues'])} entities with incorrect counts![/red]")
        console.print("\nExamples:")
        table = Table(box=box.ROUNDED)
        table.add_column("Entity", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Stored Count", style="red", justify="right")
        table.add_column("Actual Count", style="green", justify="right")
        
        for issue in stats['integrity_issues'][:5]:
            table.add_row(
                issue['value'],
                issue.get('entity_type', entity_type or 'N/A'),
                str(issue['stored_count']),
                str(issue['actual_count'])
            )
        
        console.print(table)
    
    if not Confirm.ask(f"\n[yellow]Proceed with fixing occurrence counts for {entity_type_name}?[/yellow]"):
        return
    
    # Run the fix
    console.print(f"\n[yellow]Updating occurrence counts...[/yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Fixing occurrence counts...", total=None)
        
        results = update_entity_occurrence_counts(session, entity_type)
        
        progress.update(task, completed=100)
    
    if results['status'] == 'success':
        console.print(f"\n[green]✓ Successfully updated occurrence counts![/green]")
        console.print(f"\nStatistics:")
        console.print(f"• NULL counts fixed: {results['nulls_fixed']}")
        console.print(f"• Counts updated: {results['updated']}")
        console.print(f"• Entities with no articles: {results['zeroed']}")
        
        stats = results['statistics']
        console.print(f"\n[bold]Final Statistics:[/bold]")
        console.print(f"• Total entities: {stats['total_entities']}")
        console.print(f"• With articles: {stats['with_articles']}")
        console.print(f"• Without articles: {stats['without_articles']}")
        console.print(f"• Max occurrence count: {stats['max_occurrence_count']}")
        console.print(f"• Average occurrence count: {stats['avg_occurrence_count']:.1f}")
        
        # Show top entities after fix
        updated_stats = get_entity_occurrence_stats(session, entity_type)
        if updated_stats.get('top_entities'):
            console.print(f"\n[bold]Top {entity_type_name} by occurrence:[/bold]")
            table = Table(box=box.ROUNDED)
            table.add_column("Entity", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Articles", style="green", justify="right")
            
            for entity in updated_stats['top_entities'][:10]:
                table.add_row(
                    entity['value'],
                    entity.get('entity_type', entity_type or 'N/A'),
                    str(entity['occurrence_count'])
                )
            
            console.print(table)
    else:
        console.print(f"\n[red]✗ Fix failed: {results.get('error', 'Unknown error')}[/red]")


def run_entity_reextraction(session, pipeline):
    """Re-extract entities from existing articles without re-clustering"""
    from sqlalchemy import text
    from cluster.core.entity_extractor import EntityExtractor
    from cluster.database_connection import EntityRepository
    
    console.print("\n[bold cyan]Entity Re-extraction[/bold cyan]\n")
    console.print("This will re-extract entities from articles without changing clusters.")
    console.print("Useful after importing new entity definitions (e.g., MITRE ATT&CK).")
    
    # Ask for time range
    days = Prompt.ask("\nDays to look back (0 for all articles)", default="30")
    days = int(days)
    
    # Ask if we should clear existing associations
    clear_existing = Confirm.ask("\n[yellow]Clear existing entity associations first?[/yellow]", default=False)
    
    if not Confirm.ask("\n[yellow]Proceed with entity re-extraction?[/yellow]"):
        return
    
    console.print(f"\n[yellow]Re-extracting entities from articles{f' (last {days} days)' if days > 0 else ' (all articles)'}...[/yellow]")
    
    try:
        # Get total article count
        if days > 0:
            count_result = session.execute(text("""
                SELECT COUNT(*) as count 
                FROM cluster.articles 
                WHERE fetched_at > NOW() - INTERVAL :days
            """), {'days': f'{days} days'}).fetchone()
        else:
            count_result = session.execute(text("""
                SELECT COUNT(*) as count FROM cluster.articles
            """)).fetchone()
        
        total_articles = count_result.count if count_result else 0
        
        if total_articles == 0:
            console.print("[yellow]No articles found in the specified time range.[/yellow]")
            return
        
        console.print(f"Total articles to process: {total_articles}")
        
        # Clear existing associations if requested
        if clear_existing:
            console.print("\n[yellow]Clearing existing entity associations...[/yellow]")
            if days > 0:
                session.execute(text("""
                    DELETE FROM cluster.article_entities 
                    WHERE article_id IN (
                        SELECT id FROM cluster.articles 
                        WHERE fetched_at > NOW() - INTERVAL :days
                    )
                """), {'days': f'{days} days'})
            else:
                session.execute(text("DELETE FROM cluster.article_entities"))
            
            # Reset occurrence counts for discovered entities
            session.execute(text("""
                UPDATE cluster.entities 
                SET occurrence_count = 0 
                WHERE is_predefined = FALSE
            """))
            
            session.commit()
            console.print("✓ Cleared existing associations")
        
        # Initialize entity extractor
        extractor = EntityExtractor(session)
        entity_repo = EntityRepository(session)
        
        # Process articles in batches
        batch_size = 100
        processed = 0
        entities_found = 0
        errors = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Extracting entities...", total=total_articles)
            
            offset = 0
            while offset < total_articles:
                # Get batch of articles
                if days > 0:
                    articles = session.execute(text("""
                        SELECT id, title, content, url
                        FROM cluster.articles
                        WHERE fetched_at > NOW() - INTERVAL :days
                        ORDER BY id
                        LIMIT :limit OFFSET :offset
                    """), {'days': f'{days} days', 'limit': batch_size, 'offset': offset}).fetchall()
                else:
                    articles = session.execute(text("""
                        SELECT id, title, content, url
                        FROM cluster.articles
                        ORDER BY id
                        LIMIT :limit OFFSET :offset
                    """), {'limit': batch_size, 'offset': offset}).fetchall()
                
                if not articles:
                    break
                
                # Process each article
                for article in articles:
                    try:
                        # Extract entities
                        entities = extractor.extract_all(
                            article.content or "", 
                            source_url=article.url
                        )
                        
                        # Link entities to article
                        entity_repo.link_entities_to_article(article.id, entities)
                        entities_found += len(entities)
                        
                    except Exception as e:
                        console.print(f"[red]Error processing article {article.id}: {e}[/red]")
                        errors += 1
                    
                    processed += 1
                    progress.update(task, completed=processed)
                
                # Commit batch
                session.commit()
                offset += batch_size
        
        # Get final statistics
        console.print(f"\n[green]✓ Entity re-extraction completed![/green]")
        console.print(f"\nStatistics:")
        console.print(f"• Articles processed: {processed}")
        console.print(f"• Entities found: {entities_found}")
        console.print(f"• Average entities per article: {entities_found / processed if processed > 0 else 0:.1f}")
        console.print(f"• Errors: {errors}")
        
        # Show top discovered entities
        if not clear_existing:
            console.print("\n[bold]Top Newly Discovered Entities:[/bold]")
            
            new_entities = session.execute(text("""
                SELECT e.value, e.entity_type, COUNT(DISTINCT ae.article_id) as article_count
                FROM cluster.entities e
                JOIN cluster.article_entities ae ON e.id = ae.entity_id
                JOIN cluster.articles a ON ae.article_id = a.id
                WHERE e.entity_type IN ('mitre_technique', 'ransomware_group', 'apt_group', 'malware_family')
                AND ((:days = 0) OR (a.fetched_at > NOW() - INTERVAL :interval))
                GROUP BY e.value, e.entity_type
                ORDER BY article_count DESC
                LIMIT 10
            """), {'days': days, 'interval': f'{days} days'}).fetchall()
            
            if new_entities:
                table = Table(box=box.ROUNDED)
                table.add_column("Entity", style="cyan")
                table.add_column("Type", style="yellow")
                table.add_column("Articles", style="green", justify="right")
                
                for entity in new_entities:
                    entity_type = entity.entity_type.replace('_', ' ').title()
                    table.add_row(entity.value, entity_type, str(entity.article_count))
                
                console.print(table)
        
    except Exception as e:
        console.print(f"\n[red]Entity re-extraction failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        session.rollback()


def view_cluster_details(session, cluster_id: int):
    """View detailed information about a specific cluster"""
    from sqlalchemy import text
    
    # Get cluster info
    cluster_info = session.execute(text("""
        SELECT 
            c.id,
            c.cluster_uuid,
            c.ranking_score,
            c.created_at,
            c.updated_at,
            COUNT(DISTINCT ca.article_id) as article_count
        FROM cluster.clusters c
        JOIN cluster.cluster_articles ca ON c.id = ca.cluster_id
        WHERE c.id = :cluster_id
        GROUP BY c.id
    """), {'cluster_id': cluster_id}).fetchone()
    
    if not cluster_info:
        console.print(f"[red]Cluster {cluster_id} not found.[/red]")
        return
    
    console.print(f"\n[bold cyan]Cluster Details - ID: {cluster_id}[/bold cyan]\n")
    
    # Basic info
    info_table = Table(box=box.SIMPLE)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("UUID", cluster_info.cluster_uuid)
    info_table.add_row("Created", cluster_info.created_at.strftime("%Y-%m-%d %H:%M:%S"))
    info_table.add_row("Updated", cluster_info.updated_at.strftime("%Y-%m-%d %H:%M:%S"))
    info_table.add_row("Ranking Score", f"{cluster_info.ranking_score:.0f}" if cluster_info.ranking_score else "Not ranked")
    info_table.add_row("Article Count", str(cluster_info.article_count))
    
    console.print(info_table)
    
    # Get articles
    articles = session.execute(text("""
        SELECT 
            a.id,
            a.title,
            a.source,
            a.url,
            COALESCE(a.published_date, a.fetched_at) as article_date,
            ca.is_primary
        FROM cluster.articles a
        JOIN cluster.cluster_articles ca ON a.id = ca.article_id
        WHERE ca.cluster_id = :cluster_id
        ORDER BY ca.is_primary DESC, article_date DESC
    """), {'cluster_id': cluster_id}).fetchall()
    
    console.print("\n[bold]Articles:[/bold]")
    for idx, article in enumerate(articles, 1):
        primary_marker = " [PRIMARY]" if article.is_primary else ""
        console.print(f"\n{idx}. {article.title}{primary_marker}")
        console.print(f"   Source: {article.source} | Date: {article.article_date.strftime('%Y-%m-%d %H:%M')}")
        console.print(f"   URL: [dim]{article.url}[/dim]")
    
    # Get shared entities
    entities = session.execute(text("""
        SELECT 
            e.entity_type,
            e.value,
            cse.occurrence_count
        FROM cluster.cluster_shared_entities cse
        JOIN cluster.entities e ON cse.entity_id = e.id
        WHERE cse.cluster_id = :cluster_id
        ORDER BY e.entity_type, cse.occurrence_count DESC
    """), {'cluster_id': cluster_id}).fetchall()
    
    if entities:
        console.print("\n[bold]Shared Entities:[/bold]")
        
        # Group by entity type
        from collections import defaultdict
        entity_groups = defaultdict(list)
        for entity in entities:
            entity_groups[entity.entity_type].append((entity.value, entity.occurrence_count))
        
        # Display entities by type
        for entity_type, values in sorted(entity_groups.items()):
            type_display = entity_type.replace('_', ' ').title()
            console.print(f"\n[yellow]{type_display}:[/yellow]")
            for value, count in values[:10]:  # Show max 10 per type
                console.print(f"  • {value} (appears in {count} articles)")
            if len(values) > 10:
                console.print(f"  [dim]... and {len(values) - 10} more[/dim]")


def view_top_threats(session):
    """View top threats by occurrence"""
    from sqlalchemy import text
    
    console.print("\n[bold cyan]Top Active Threats (Last 7 Days)[/bold cyan]\n")
    
    # Create table
    table = Table(box=box.ROUNDED)
    table.add_column("Threat Actor", style="red", no_wrap=True)
    table.add_column("Type", style="yellow")
    table.add_column("Articles", style="green", justify="right")
    table.add_column("Clusters", style="cyan", justify="right")
    table.add_column("First Seen", style="magenta")
    
    result = session.execute(text("""
        SELECT 
            e.value as threat,
            e.entity_type,
            COUNT(DISTINCT ae.article_id) as article_count,
            COUNT(DISTINCT ca.cluster_id) as cluster_count,
            MIN(a.fetched_at) as first_seen
        FROM cluster.entities e
        JOIN cluster.article_entities ae ON e.id = ae.entity_id
        JOIN cluster.articles a ON ae.article_id = a.id
        LEFT JOIN cluster.cluster_articles ca ON a.id = ca.article_id
        WHERE e.entity_type IN ('ransomware_group', 'apt_group', 'malware_family')
        AND a.fetched_at > NOW() - INTERVAL '7 days'
        GROUP BY e.value, e.entity_type
        ORDER BY article_count DESC
        LIMIT 15
    """)).fetchall()
    
    for row in result:
        entity_type = row.entity_type.replace('_', ' ').title()
        first_seen = row.first_seen.strftime("%Y-%m-%d %H:%M") if row.first_seen else "Unknown"
        
        table.add_row(
            row.threat,
            entity_type,
            str(row.article_count),
            str(row.cluster_count),
            first_seen
        )
    
    console.print(table)


def run_full_recluster(session, pipeline):
    """Re-cluster all articles from scratch"""
    from sqlalchemy import text
    
    console.print("\n[bold red]⚠️  WARNING: Full Re-clustering[/bold red]")
    console.print("This will:")
    console.print("• Deactivate ALL existing clusters")
    console.print("• Re-extract entities from ALL articles")
    console.print("• Create new clusters from scratch")
    console.print("• This process may take a long time depending on your data")
    
    if not Confirm.ask("\n[yellow]Are you absolutely sure you want to continue?[/yellow]"):
        console.print("[green]Re-clustering cancelled.[/green]")
        return
    
    # Double confirm for safety
    confirm_text = Prompt.ask("\nType 'RECLUSTER' to confirm")
    if confirm_text != "RECLUSTER":
        console.print("[green]Re-clustering cancelled.[/green]")
        return
    
    console.print("\n[bold cyan]Starting Full Re-cluster Process[/bold cyan]")
    
    try:
        # Step 1: Get total article count
        total_articles_result = session.execute(text("""
            SELECT COUNT(*) as count FROM cluster.articles
        """)).fetchone()
        total_articles = total_articles_result.count if total_articles_result else 0
        
        console.print(f"\nTotal articles to process: {total_articles}")
        
        # Step 2: Deactivate all existing clusters
        console.print("\n[yellow]Step 1/4: Deactivating existing clusters...[/yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Deactivating clusters...", total=None)
            
            deactivate_result = session.execute(text("""
                UPDATE cluster.clusters 
                SET is_active = FALSE 
                WHERE is_active = TRUE
                RETURNING id
            """))
            deactivated_count = deactivate_result.rowcount
            session.commit()
            
            progress.update(task, completed=100)
        
        console.print(f"✓ Deactivated {deactivated_count} clusters")
        
        # Step 3: Clear article-entity associations (optional - might want to keep for reference)
        if Confirm.ask("\n[yellow]Clear existing entity associations? (recommended for clean re-cluster)[/yellow]", default=True):
            console.print("\n[yellow]Step 2/4: Clearing entity associations...[/yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Clearing associations...", total=None)
                
                # Clear article-entity associations
                session.execute(text("DELETE FROM cluster.article_entities"))
                
                # Reset occurrence counts for discovered entities
                session.execute(text("""
                    UPDATE cluster.entities 
                    SET occurrence_count = 0 
                    WHERE is_predefined = FALSE
                """))
                
                session.commit()
                progress.update(task, completed=100)
            
            console.print("✓ Cleared entity associations")
        
        # Step 4: Re-extract entities from all articles
        console.print("\n[yellow]Step 3/4: Re-extracting entities from all articles...[/yellow]")
        
        # Import entity extractor
        from cluster.core.entity_extractor import EntityExtractor
        extractor = EntityExtractor(session)
        
        # Process articles in batches
        batch_size = 100
        processed = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Extracting entities...", total=total_articles)
            
            offset = 0
            while offset < total_articles:
                # Get batch of articles
                articles = session.execute(text("""
                    SELECT id, title, content, url
                    FROM cluster.articles
                    ORDER BY id
                    LIMIT :limit OFFSET :offset
                """), {'limit': batch_size, 'offset': offset}).fetchall()
                
                if not articles:
                    break
                
                # Process each article
                for article in articles:
                    try:
                        # Extract entities
                        entities = extractor.extract_all(
                            article.content or "", 
                            source_url=article.url
                        )
                        
                        # Link entities to article
                        from cluster.database_connection import EntityRepository
                        entity_repo = EntityRepository(session)
                        entity_repo.link_entities_to_article(article.id, entities)
                        
                    except Exception as e:
                        console.print(f"[red]Error processing article {article.id}: {e}[/red]")
                    
                    processed += 1
                    progress.update(task, completed=processed)
                
                # Commit batch
                session.commit()
                offset += batch_size
        
        console.print(f"✓ Re-extracted entities from {processed} articles")
        
        # Step 5: Run clustering on all articles
        console.print("\n[yellow]Step 4/4: Creating new clusters...[/yellow]")
        
        # Run clustering with no time limit to process all articles
        cluster_results = run_stage_with_progress(
            "Full clustering", 
            pipeline.cluster_articles, 
            999999  # Process all articles (very large number of days)
        )
        display_cluster_results(cluster_results)
        
        # Step 6: Update rankings for new clusters
        console.print("\n[yellow]Bonus Step: Updating rankings...[/yellow]")
        ranking_results = run_stage_with_progress("Ranking update", pipeline.update_rankings)
        display_ranking_results(ranking_results)
        
        # Final statistics
        console.print("\n[bold green]✓ Re-clustering Complete![/bold green]")
        
        # Get final stats
        final_stats = session.execute(text("""
            SELECT 
                (SELECT COUNT(*) FROM cluster.clusters WHERE is_active = TRUE) as active_clusters,
                (SELECT COUNT(DISTINCT article_id) FROM cluster.cluster_articles ca 
                 JOIN cluster.clusters c ON ca.cluster_id = c.id 
                 WHERE c.is_active = TRUE) as clustered_articles,
                (SELECT COUNT(DISTINCT entity_id) FROM cluster.article_entities) as unique_entities
        """)).fetchone()
        
        if final_stats:
            console.print(f"\nFinal Statistics:")
            console.print(f"• Active Clusters: {final_stats.active_clusters}")
            console.print(f"• Clustered Articles: {final_stats.clustered_articles}")
            console.print(f"• Unique Entities: {final_stats.unique_entities}")
        
    except Exception as e:
        console.print(f"\n[red]Re-clustering failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        # Rollback on error
        session.rollback()


def run_continuous_mode(pipeline):
    """Run pipeline continuously with monitoring"""
    interval = Prompt.ask("Run interval (minutes)", default="10")
    interval_minutes = int(interval)
    
    console.print(f"\n[bold cyan]Starting Continuous Mode[/bold cyan]")
    console.print(f"Pipeline will run every {interval_minutes} minutes")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
    
    run_count = 0
    
    while not shutdown_requested:
        run_count += 1
        
        # Clear screen and show header
        console.clear()
        console.print(f"[bold cyan]ThreatCluster Continuous Mode[/bold cyan]")
        console.print(f"Run #{run_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        console.print("─" * 50)
        
        try:
            # Run pipeline
            console.print("\n[yellow]Starting pipeline run...[/yellow]")
            
            # Collect feeds
            feed_results = pipeline.collect_feeds()
            console.print(f"✓ Feeds: {feed_results.get('security_relevant', 0)}/{feed_results.get('total_fetched', 0)} relevant")
            
            # Cluster
            cluster_results = pipeline.cluster_articles()
            console.print(f"✓ Clusters: {cluster_results.get('clusters_created', 0)} new, {cluster_results.get('clusters_updated', 0)} updated")
            
            # Refresh entities
            entity_results = pipeline.refresh_entities()
            total_discovered = sum(entity_results.get('discovered', {}).values())
            console.print(f"✓ Entities: {total_discovered} discovered")
            
            # Update rankings
            ranking_results = pipeline.update_rankings()
            console.print(f"✓ Rankings: {ranking_results.get('clusters_ranked', 0)} clusters ranked")
            
            console.print("\n[green]✓ Run completed successfully[/green]")
            
        except Exception as e:
            console.print(f"\n[red]✗ Run failed: {e}[/red]")
        
        # Wait for next run
        if not shutdown_requested:
            console.print(f"\n[dim]Next run in {interval_minutes} minutes...[/dim]")
            
            # Sleep in small increments to check for shutdown
            for _ in range(interval_minutes * 60):
                if shutdown_requested:
                    break
                time.sleep(1)
    
    console.print("\n[yellow]Continuous mode stopped[/yellow]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="ThreatCluster - Cybersecurity News Aggregation & Clustering System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended)
  python threatcluster_cli.py

  # Run full pipeline once
  python threatcluster_cli.py --run-once

  # Run specific stage
  python threatcluster_cli.py --stage feeds
  python threatcluster_cli.py --stage cluster --days 7

  # Re-cluster everything from scratch
  python threatcluster_cli.py --recluster

  # Continuous mode
  python threatcluster_cli.py --continuous --interval 15
  
  # Import threat actors from MISP Galaxy
  python threatcluster_cli.py --import-misp all
  python threatcluster_cli.py --import-misp ransomware
  python threatcluster_cli.py --import-misp apt
  python threatcluster_cli.py --import-misp malware
  
  # Import MITRE ATT&CK techniques
  python threatcluster_cli.py --import-mitre-attack
  
  # Re-extract entities from existing articles
  python threatcluster_cli.py --reextract-entities --days 30
        """
    )
    
    parser.add_argument('--run-once', action='store_true',
                       help='Run full pipeline once and exit')
    parser.add_argument('--stage', choices=['feeds', 'cluster', 'entities', 'rank'],
                       help='Run specific stage only')
    parser.add_argument('--continuous', action='store_true',
                       help='Run in continuous mode')
    parser.add_argument('--interval', type=int, default=10,
                       help='Interval in minutes for continuous mode (default: 10)')
    parser.add_argument('--days', type=int, default=14,
                       help='Days to look back for clustering/entities (default: 14)')
    parser.add_argument('--recluster', action='store_true',
                       help='Re-cluster all articles from scratch')
    parser.add_argument('--import-misp', choices=['all', 'ransomware', 'apt', 'malware'],
                       help='Import threat actors from MISP Galaxy')
    parser.add_argument('--import-mitre-attack', action='store_true',
                       help='Import MITRE ATT&CK techniques')
    parser.add_argument('--reextract-entities', action='store_true',
                       help='Re-extract entities from existing articles without re-clustering')
    parser.add_argument('--quiet', action='store_true',
                       help='Minimal output')
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        with db_manager.session() as session:
            pipeline = create_pipeline(session)
            
            if args.recluster:
                # Run full re-cluster
                if not args.quiet:
                    print_banner()
                
                run_full_recluster(session, pipeline)
                
            elif args.import_misp:
                # Import from MISP Galaxy
                if not args.quiet:
                    print_banner()
                
                import asyncio
                from core.misp_galaxy_importer import MISPGalaxyImporter
                
                importer = MISPGalaxyImporter(session)
                
                # Map argument values to entity types
                entity_map = {
                    'all': ['ransomware_group', 'apt_group', 'malware_family'],
                    'ransomware': ['ransomware_group'],
                    'apt': ['apt_group'],
                    'malware': ['malware_family']
                }
                
                entity_types = entity_map[args.import_misp]
                
                console.print(f"[bold cyan]Importing {args.import_misp} from MISP Galaxy[/bold cyan]\n")
                
                # Run import
                if args.import_misp == 'all':
                    results = asyncio.run(importer.import_all())
                else:
                    results = asyncio.run(importer.import_specific(entity_types))
                
                # Display results
                if not args.quiet:
                    total_stats = results['total_stats']
                    console.print(f"\n[green]✓ Import completed:[/green]")
                    console.print(f"  • Processed: {total_stats['total_processed']}")
                    console.print(f"  • New: {total_stats['new_entities']}")
                    console.print(f"  • Updated: {total_stats['updated_entities']}")
                    console.print(f"  • Errors: {total_stats['errors']}")
                
            elif args.import_mitre_attack:
                # Import MITRE ATT&CK techniques
                if not args.quiet:
                    print_banner()
                
                import asyncio
                from core.mitre_attack_importer import MITREAttackImporter
                
                console.print("[bold cyan]Importing MITRE ATT&CK Techniques[/bold cyan]\n")
                
                importer = MITREAttackImporter(session)
                results = asyncio.run(importer.import_techniques())
                
                if results['status'] == 'success':
                    stats = results['stats']
                    if not args.quiet:
                        console.print(f"\n[green]✓ Import completed:[/green]")
                        console.print(f"  • Processed: {stats['total_processed']}")
                        console.print(f"  • New: {stats['new_entities']}")
                        console.print(f"  • Updated: {stats['updated_entities']}")
                        console.print(f"  • Errors: {stats['errors']}")
                else:
                    console.print(f"\n[red]✗ Import failed: {results['message']}[/red]")
                
            elif args.reextract_entities:
                # Re-extract entities
                if not args.quiet:
                    print_banner()
                
                console.print("[bold cyan]Re-extracting Entities[/bold cyan]\n")
                
                # Use a simplified version for command line
                from sqlalchemy import text
                from cluster.core.entity_extractor import EntityExtractor
                from cluster.database_connection import EntityRepository
                
                # Get article count for specified days
                if args.days > 0:
                    count_result = session.execute(text("""
                        SELECT COUNT(*) as count 
                        FROM cluster.articles 
                        WHERE fetched_at > NOW() - INTERVAL :days
                    """), {'days': f'{args.days} days'}).fetchone()
                else:
                    count_result = session.execute(text("""
                        SELECT COUNT(*) as count FROM cluster.articles
                    """)).fetchone()
                
                total_articles = count_result.count if count_result else 0
                
                if total_articles == 0:
                    console.print("[yellow]No articles found.[/yellow]")
                else:
                    console.print(f"Processing {total_articles} articles...")
                    
                    extractor = EntityExtractor(session)
                    entity_repo = EntityRepository(session)
                    
                    # Process in batches
                    batch_size = 100
                    processed = 0
                    entities_found = 0
                    
                    offset = 0
                    while offset < total_articles:
                        if args.days > 0:
                            articles = session.execute(text("""
                                SELECT id, title, content, url
                                FROM cluster.articles
                                WHERE fetched_at > NOW() - INTERVAL :days
                                ORDER BY id
                                LIMIT :limit OFFSET :offset
                            """), {'days': f'{args.days} days', 'limit': batch_size, 'offset': offset}).fetchall()
                        else:
                            articles = session.execute(text("""
                                SELECT id, title, content, url
                                FROM cluster.articles
                                ORDER BY id
                                LIMIT :limit OFFSET :offset
                            """), {'limit': batch_size, 'offset': offset}).fetchall()
                        
                        if not articles:
                            break
                        
                        for article in articles:
                            try:
                                entities = extractor.extract_all(
                                    article.content or "", 
                                    source_url=article.url
                                )
                                entity_repo.link_entities_to_article(article.id, entities)
                                entities_found += len(entities)
                                processed += 1
                            except:
                                pass
                        
                        session.commit()
                        offset += batch_size
                        
                        if not args.quiet:
                            console.print(f"Processed {processed}/{total_articles} articles...")
                    
                    if not args.quiet:
                        console.print(f"\n[green]✓ Re-extraction completed:[/green]")
                        console.print(f"  • Articles: {processed}")
                        console.print(f"  • Entities: {entities_found}")
                
            elif args.run_once:
                # Run full pipeline once
                if not args.quiet:
                    print_banner()
                
                console.print("[bold cyan]Running Full Pipeline[/bold cyan]\n")
                
                results = pipeline.run_full_pipeline()
                
                if not args.quiet:
                    console.print("\n[bold]Pipeline Results:[/bold]")
                    console.print(f"• Feeds: {results['feed_collection'].get('security_relevant', 0)} relevant articles")
                    console.print(f"• Clusters: {results['clustering'].get('clusters_created', 0)} created")
                    console.print(f"• Entities: {sum(results['entity_refresh'].get('discovered', {}).values())} discovered")
                    console.print(f"• Rankings: {results['ranking'].get('clusters_ranked', 0)} clusters ranked")
                
                console.print("\n[green]✓ Pipeline completed[/green]")
                
            elif args.stage:
                # Run specific stage
                if not args.quiet:
                    print_banner()
                
                if args.stage == 'feeds':
                    results = pipeline.collect_feeds()
                    if not args.quiet:
                        display_feed_results(results)
                
                elif args.stage == 'cluster':
                    results = pipeline.cluster_articles(args.days)
                    if not args.quiet:
                        display_cluster_results(results)
                
                elif args.stage == 'entities':
                    results = pipeline.refresh_entities(args.days)
                    if not args.quiet:
                        display_entity_results(results)
                
                elif args.stage == 'rank':
                    results = pipeline.update_rankings()
                    if not args.quiet:
                        display_ranking_results(results)
                
                console.print(f"\n[green]✓ Stage '{args.stage}' completed[/green]")
                
            elif args.continuous:
                # Continuous mode
                if not args.quiet:
                    print_banner()
                
                console.print(f"[bold cyan]Starting Continuous Mode[/bold cyan]")
                console.print(f"Interval: {args.interval} minutes\n")
                
                # Set up signal handler
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
                
                while not shutdown_requested:
                    try:
                        results = pipeline.run_full_pipeline()
                        
                        if not args.quiet:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            console.print(f"[{timestamp}] Run completed - "
                                        f"Feeds: {results['feed_collection'].get('security_relevant', 0)}, "
                                        f"Clusters: {results['clustering'].get('clusters_created', 0)}")
                        
                    except Exception as e:
                        console.print(f"[red]Error: {e}[/red]")
                    
                    # Wait for next run
                    if not shutdown_requested:
                        for _ in range(args.interval * 60):
                            if shutdown_requested:
                                break
                            time.sleep(1)
                
                console.print("\n[yellow]Continuous mode stopped[/yellow]")
                
            else:
                # Interactive mode
                interactive_mode()
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        logging.error("Fatal error", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()