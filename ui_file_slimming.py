#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件夹搜身UI模块
用于文件夹管理工具（Myfile）
"""

from typing import Optional, Any, List, Dict
import os

try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
        QPushButton, QProgressBar, QGroupBox, QSplitter, 
        QTableWidget, QTableWidgetItem, QHeaderView, 
        QAbstractItemView, QSizePolicy, QMenu
    )
    from PyQt6.QtCore import Qt, QPoint
    from PyQt6.QtGui import QAction
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

from ui_components import UIStyles, UIUtils, FileTableWidgetItem


class FileSlimmingUI:
    """文件夹搜身UI类"""

    def __init__(self, parent: Any):
        """
        初始化文件夹搜身UI

        Args:
            parent: 父窗口或主应用实例
        """
        self.parent = parent
        self._init_ui_components()

    def _init_ui_components(self) -> None:
        """初始化UI组件"""
        if not PYQT_AVAILABLE:
            return

        self.file_slimming_folder_edit = None
        self.file_slimming_browse_btn = None
        self.file_slimming_start_btn = None
        self.file_slimming_pause_btn = None
        self.file_slimming_stop_btn = None
        self.file_slimming_progress_bar = None
        self.file_slimming_files_table = None
        self.file_slimming_current_file_label = None
        self.file_slimming_delete_btn = None

    def create_file_slimming_folder_selector(self, callback: Any) -> tuple:
        """
        创建文件夹选择器

        Args:
            callback: 浏览按钮回调函数

        Returns:
            tuple: (输入框, 浏览按钮, 组)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        group = QGroupBox("选择文件夹")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN,
                                UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN)
        layout.setSpacing(UIStyles.LAYOUT_SPACING)

        edit = QLineEdit()
        edit.setPlaceholderText("选择要扫描的文件夹")
        edit.setFixedHeight(UIStyles.INPUT_HEIGHT)
        edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        browse_btn = UIUtils.create_browse_button(callback)

        layout.addWidget(edit, 1)
        layout.addWidget(browse_btn)

        layout.setAlignment(edit, Qt.AlignmentFlag.AlignVCenter)
        layout.setAlignment(browse_btn, Qt.AlignmentFlag.AlignVCenter)

        self.file_slimming_folder_edit = edit

        return edit, browse_btn, group

    def create_file_slimming_buttons(self) -> tuple:
        """
        创建控制按钮

        Returns:
            tuple: (开始按钮, 暂停按钮, 停止按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None, None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        start_btn = UIUtils.create_button("开始扫描")
        pause_btn = UIUtils.create_button("暂停")
        stop_btn = UIUtils.create_button("停止")

        pause_btn.setEnabled(False)
        stop_btn.setEnabled(False)

        layout.addWidget(start_btn)
        layout.addWidget(pause_btn)
        layout.addWidget(stop_btn)

        self.file_slimming_start_btn = start_btn
        self.file_slimming_pause_btn = pause_btn
        self.file_slimming_stop_btn = stop_btn

        return start_btn, pause_btn, stop_btn, layout

    def create_file_slimming_progress_area(self) -> tuple:
        """
        创建进度区域

        Returns:
            tuple: (进度条, 当前文件标签, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        layout = QVBoxLayout()

        progress_bar = UIUtils.create_progress_bar()
        layout.addWidget(progress_bar)

        current_file_label = QLabel("当前文件：无")
        layout.addWidget(current_file_label)

        self.file_slimming_progress_bar = progress_bar
        self.file_slimming_current_file_label = current_file_label

        return progress_bar, current_file_label, layout

    def create_file_slimming_files_table(self) -> QTableWidget:
        """
        创建文件表格

        Returns:
            QTableWidget: 文件表格
        """
        if not PYQT_AVAILABLE:
            return None

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["文件名", "大小", "修改时间", "路径"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSortingEnabled(True)

        self.file_slimming_files_table = table

        return table

    def create_file_slimming_operations(self) -> tuple:
        """
        创建操作区域

        Returns:
            tuple: (删除选中按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        delete_btn = UIUtils.create_button("删除选中文件")
        layout.addWidget(delete_btn)

        self.file_slimming_delete_btn = delete_btn

        return delete_btn, layout

    def set_folder(self, path: str) -> None:
        """
        设置文件夹路径

        Args:
            path: 文件夹路径
        """
        if self.file_slimming_folder_edit:
            self.file_slimming_folder_edit.setText(path)

    def get_folder(self) -> str:
        """
        获取文件夹路径

        Returns:
            str: 文件夹路径
        """
        if self.file_slimming_folder_edit:
            return self.file_slimming_folder_edit.text().strip()
        return ""

    def set_buttons_enabled(self, enabled: bool) -> None:
        """
        设置按钮启用状态

        Args:
            enabled: 是否启用
        """
        if self.file_slimming_start_btn:
            self.file_slimming_start_btn.setEnabled(enabled)
        if self.file_slimming_pause_btn:
            self.file_slimming_pause_btn.setEnabled(not enabled)
        if self.file_slimming_stop_btn:
            self.file_slimming_stop_btn.setEnabled(not enabled)

    def update_progress(self, value: int) -> None:
        """
        更新进度

        Args:
            value: 进度值 (0-100)
        """
        if self.file_slimming_progress_bar:
            self.file_slimming_progress_bar.setValue(value)

    def update_current_file(self, file_path: str) -> None:
        """
        更新当前文件

        Args:
            file_path: 文件路径
        """
        if self.file_slimming_current_file_label:
            file_name = os.path.basename(file_path) if file_path else "无"
            self.file_slimming_current_file_label.setText(f"当前文件：{file_name}")

    def clear_table(self) -> None:
        """清空表格"""
        if self.file_slimming_files_table:
            self.file_slimming_files_table.setRowCount(0)

    def display_files(self, files_data: List[Dict[str, Any]]) -> None:
        """
        显示文件列表

        Args:
            files_data: 文件数据列表
        """
        if not self.file_slimming_files_table:
            return

        self.file_slimming_files_table.setSortingEnabled(False)
        self.file_slimming_files_table.setRowCount(0)

        for i, file_info in enumerate(files_data):
            self.file_slimming_files_table.insertRow(i)

            name = file_info.get("name", "")
            size = file_info.get("size", 0)
            modified = file_info.get("modified", "")
            path = file_info.get("full_path", "")

            name_item = QTableWidgetItem(name)
            self.file_slimming_files_table.setItem(i, 0, name_item)

            size_str = UIUtils.format_file_size(size)
            size_item = FileTableWidgetItem(size_str, file_size=size)
            self.file_slimming_files_table.setItem(i, 1, size_item)

            modified_item = QTableWidgetItem(modified)
            self.file_slimming_files_table.setItem(i, 2, modified_item)

            path_item = QTableWidgetItem(path)
            self.file_slimming_files_table.setItem(i, 3, path_item)

        self.file_slimming_files_table.setSortingEnabled(True)
        self.file_slimming_files_table.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    def get_selected_rows(self) -> List[int]:
        """
        获取选中的行

        Returns:
            List[int]: 选中行的索引列表
        """
        if not self.file_slimming_files_table:
            return []

        selected_items = self.file_slimming_files_table.selectedItems()
        if not selected_items:
            return []

        rows = set()
        for item in selected_items:
            rows.add(item.row())

        return sorted(list(rows))

    def get_selected_files(self) -> List[str]:
        """
        获取选中的文件路径

        Returns:
            List[str]: 选中文件的路径列表
        """
        if not self.file_slimming_files_table:
            return []

        selected_files = []
        for row in self.get_selected_rows():
            path_item = self.file_slimming_files_table.item(row, 3)
            if path_item:
                selected_files.append(path_item.text())

        return selected_files
