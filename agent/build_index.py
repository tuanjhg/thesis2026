"""
Build (or rebuild) the RAG knowledge base index.

Run once before using the SOC Agent:
  cd D:/Khóa luận/Src_2
  python agent/build_index.py

Options:
  --force     Delete and rebuild all collections
  --stats     Show current collection stats only (no rebuild)
  --kb-dir    Override KB storage path (default: agent/rag/kb_store/)
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Project root on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "agent"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Build PAD-ONAP RAG Knowledge Base")
    parser.add_argument("--force",  action="store_true", help="Delete and rebuild all collections")
    parser.add_argument("--stats",  action="store_true", help="Show stats only, no rebuild")
    parser.add_argument("--kb-dir", default=None, help="Override KB storage path")
    args = parser.parse_args()

    if args.kb_dir:
        os.environ["KB_DIR"] = args.kb_dir

    try:
        from rag.knowledge_base import build_index, collection_stats
    except ImportError as e:
        print(f"\nERROR: {e}")
        print("\nInstall RAG dependencies first:")
        print("  pip install chromadb sentence-transformers")
        sys.exit(1)

    if args.stats:
        stats = collection_stats()
        print("\nKnowledge Base Collections:")
        for name, count in stats.items():
            status = "OK" if count > 0 else "EMPTY"
            print(f"  [{status}] {name:<25} {count} documents")
        return

    print(f"\nBuilding knowledge base at: {os.environ.get('KB_DIR', 'agent/rag/kb_store/')}")
    print(f"Project root: {PROJECT_ROOT}")
    if args.force:
        print("Mode: FORCE REBUILD (deleting existing collections)")
    else:
        print("Mode: INCREMENTAL (skip if already built)")

    print("\nDownloading embedding model (first run may take ~1 min)...")
    counts = build_index(project_root=str(PROJECT_ROOT), force=args.force)

    print("\n✓ Knowledge base ready:")
    for collection, count in counts.items():
        print(f"  {collection:<25} {count} documents")

    print("\nTest query:")
    from rag.knowledge_base import query_knowledge_base
    results = query_knowledge_base(
        "SYN flood proactive lead time 30 seconds",
        collection="lead_time",
        n_results=1,
    )
    if results and "error" not in results[0]:
        print(f"  Query OK — top result distance: {results[0].get('distance', '?')}")
        print(f"  Preview: {results[0]['document'][:120]}...")
    else:
        print(f"  Query result: {results}")


if __name__ == "__main__":
    main()
