#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试表格排序功能
"""

from PyQt6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from ui_components import FileTableWidgetItem
import sys

def test_table_sorting():
    """测试表格排序"""
    app = QApplication(sys.argv)

    table = QTableWidget()
    table.setColumnCount(2)
    table.setHorizontalHeaderLabels(["文件名", "大小"])
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.setSortingEnabled(True)

    files = [
        ("1.5 KB", 1536),
        ("10 MB", 10485760),
        ("500 B", 500),
        ("2 GB", 2147483648),
        ("100 KB", 102400),
    ]

    print("添加数据到表格...")
    for i, (name, size) in enumerate(files):
        table.insertRow(i)

        name_item = QTableWidgetItem(name)
        table.setItem(i, 0, name_item)

        size_item = FileTableWidgetItem(name, file_size=size)
        table.setItem(i, 1, size_item)

    print("\n排序前:")
    for row in range(table.rowCount()):
        name = table.item(row, 0).text()
        size_item = table.item(row, 1)
        size = size_item.file_size if hasattr(size_item, 'file_size') else 0
        print(f"  {name} ({size} bytes)")

    print("\n执行降序排序...")
    table.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    print("\n排序后:")
    for row in range(table.rowCount()):
        name = table.item(row, 0).text()
        size_item = table.item(row, 1)
        size = size_item.file_size if hasattr(size_item, 'file_size') else 0
        print(f"  {name} ({size} bytes)")

    expected_sizes = [2147483648, 10485760, 102400, 1536, 500]
    actual_sizes = []
    for row in range(table.rowCount()):
        size_item = table.item(row, 1)
        size = size_item.file_size if hasattr(size_item, 'file_size') else 0
        actual_sizes.append(size)

    if actual_sizes == expected_sizes:
        print("\n✓ 表格排序正确！")
        return True
    else:
        print("\n✗ 表格排序错误！")
        print(f"期望: {expected_sizes}")
        print(f"实际: {actual_sizes}")
        return False

if __name__ == "__main__":
    try:
        result = test_table_sorting()
        exit(0 if result else 1)
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
