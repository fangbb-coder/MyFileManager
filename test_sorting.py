#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试文件大小排序功能
"""

from ui_components import FileTableWidgetItem
from PyQt6.QtCore import Qt

def test_sorting():
    """测试文件大小排序"""
    items = [
        FileTableWidgetItem("1.5 KB", file_size=1536),
        FileTableWidgetItem("10 MB", file_size=10485760),
        FileTableWidgetItem("500 B", file_size=500),
        FileTableWidgetItem("2 GB", file_size=2147483648),
        FileTableWidgetItem("100 KB", file_size=102400),
    ]

    print("排序前:")
    for item in items:
        print(f"  {item.text()} ({item.file_size} bytes)")

    items.sort(reverse=True)

    print("\n降序排序后:")
    for item in items:
        print(f"  {item.text()} ({item.file_size} bytes)")

    expected_sizes = [2147483648, 10485760, 102400, 1536, 500]
    actual_sizes = [item.file_size for item in items]

    if actual_sizes == expected_sizes:
        print("\n✓ 排序正确！")
        return True
    else:
        print("\n✗ 排序错误！")
        print(f"期望: {expected_sizes}")
        print(f"实际: {actual_sizes}")
        return False

if __name__ == "__main__":
    try:
        result = test_sorting()
        exit(0 if result else 1)
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
