#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Qt排序常量
"""

from PyQt6.QtCore import Qt

print("Testing Qt.SortOrder:")
print(f"  Qt.SortOrder.DescendingOrder = {Qt.SortOrder.DescendingOrder}")
print(f"  Qt.SortOrder.AscendingOrder = {Qt.SortOrder.AscendingOrder}")

print("\nTesting Qt.ItemDataRole:")
print(f"  Qt.ItemDataRole.UserRole = {Qt.ItemDataRole.UserRole}")
print(f"  Qt.ItemDataRole.DisplayRole = {Qt.ItemDataRole.DisplayRole}")

print("\nTesting Qt constants:")
print(f"  Qt.DescendingOrder = {Qt.DescendingOrder}")
print(f"  Qt.AscendingOrder = {Qt.AscendingOrder}")
print(f"  Qt.UserRole = {Qt.UserRole}")
