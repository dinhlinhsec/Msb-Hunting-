#!/usr/bin/env python3
"""
msb.com.vn
linh@msb.com.vn
MSB GitHub Threat Hunter - Dashboard CLI
Xem thống kê và báo cáo qua command line
"""

import sys
import json
import argparse
from datetime import datetime
from database import Database
from config import Config


def print_header():
    print("\n" + "="*65)
    print("     🔍  MSB GitHub Threat Hunter - Security Dashboard")
    print("="*65)


def cmd_stats(db: Database):
    """Hiển thị thống kê tổng quan"""
    stats = db.get_stats()
    print_header()
    print(f"\n📊 THỐNG KÊ TỔNG QUAN")
    print(f"  Tổng files đã quét  : {stats['total_files_scanned']:,}")
    print(f"  Tổng alerts phát hiện: {stats['total_alerts']:,}")

    if stats['severity_distribution']:
        print(f"\n⚠️  PHÂN BỐ SEVERITY:")
        for row in sorted(stats['severity_distribution'],
                          key=lambda x: {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(x['severity'],0),
                          reverse=True):
            bar = '█' * min(row['cnt'], 30)
            print(f"  {row['severity']:<10} {row['cnt']:>5}  {bar}")

    if stats['top_users']:
        print(f"\n👤 TOP USERS CÓ ALERTS:")
        for i, row in enumerate(stats['top_users'], 1):
            print(f"  {i}. {row['username']:<30} {row['cnt']:>5} alert(s)")

    print()


def cmd_recent(db: Database, limit: int = 20):
    """Hiển thị alerts gần đây"""
    alerts = db.get_recent_alerts(limit)
    print_header()
    print(f"\n🚨 {len(alerts)} ALERTS GẦN ĐÂY\n")

    if not alerts:
        print("  Chưa có alert nào.")
        return

    for a in alerts:
        try:
            matches = json.loads(a['matches_json'])
        except Exception:
            matches = []

        sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(a['severity'], '⚪')
        print(f"  {sev_emoji} [{a['severity']}] {a['alerted_at']}")
        print(f"     User   : {a['username']}")
        print(f"     Repo   : {a['repo']}")
        print(f"     File   : {a['filename']}")
        print(f"     Pattern: {a['pattern_name']}")
        print(f"     Matches: {matches[:3]}")
        print(f"     Commit : {a['commit_url']}")
        print()


def cmd_export(db: Database, output_file: str):
    """Export alerts ra file JSON"""
    alerts = db.get_recent_alerts(limit=10000)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'exported_at': datetime.utcnow().isoformat() + 'Z',
            'total': len(alerts),
            'alerts': alerts
        }, f, ensure_ascii=False, indent=2)
    print(f"✅ Đã export {len(alerts)} alerts ra {output_file}")


def cmd_users(db: Database):
    """Liệt kê users đang được theo dõi"""
    config = Config()
    print_header()
    print(f"\n👥 DANH SÁCH USERS ĐANG THEO DÕI ({len(config.MONITORED_USERS)}):\n")
    for i, user in enumerate(config.MONITORED_USERS, 1):
        print(f"  {i:>3}. {user}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='MSB GitHub Threat Hunter - Dashboard CLI'
    )
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('stats', help='Xem thống kê tổng quan')
    recent_p = subparsers.add_parser('recent', help='Xem alerts gần đây')
    recent_p.add_argument('-n', '--limit', type=int, default=20, help='Số lượng (mặc định: 20)')
    export_p = subparsers.add_parser('export', help='Export alerts ra JSON')
    export_p.add_argument('-o', '--output', default='alerts_export.json', help='File output')
    subparsers.add_parser('users', help='Xem danh sách users đang theo dõi')

    args = parser.parse_args()

    config = Config()
    db = Database(config.DB_PATH)

    if args.command == 'stats':
        cmd_stats(db)
    elif args.command == 'recent':
        cmd_recent(db, args.limit)
    elif args.command == 'export':
        cmd_export(db, args.output)
    elif args.command == 'users':
        cmd_users(db)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
