#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重复文件查找UI模块
用于文件夹管理工具（Myfile）
"""

from typing import Optional, Any, List, Dict
import os

try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
        QPushButton, QProgressBar, QGroupBox, QSplitter, 
        QTableWidget, QTableWidgetItem, QHeaderView, 
        QAbstractItemView, QSizePolicy, QCheckBox, QMenu
    )
    from PyQt6.QtCore import Qt, QPoint
    from PyQt6.QtGui import QAction
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

from ui_components import UIStyles, UIUtils, FileTableWidgetItem


class DuplicateFinderUI:
    """重复文件查找UI类"""

    def __init__(self, parent: Any):
        """
        初始化重复文件查找UI

        Args:
            parent: 父窗口或主应用实例
        """
        self.parent = parent
        self._init_ui_components()

    def _init_ui_components(self) -> None:
        """初始化UI组件"""
        if not PYQT_AVAILABLE:
            return

        self.duplicate_folder_edit = None
        self.duplicate_browse_btn = None
        self.duplicate_find_btn = None
        self.duplicate_progress_bar = None
        self.duplicate_files_table = None
        self.duplicate_help_label = None
        self.deselect_all_btn = None
        self.delete_selected_btn = None

    def create_duplicate_folder_selector(self, callback: Any) -> tuple:
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

        self.duplicate_folder_edit = edit

        return edit, browse_btn, group

    def create_duplicate_buttons(self) -> tuple:
        """
        创建查找控制按钮

        Returns:
            tuple: (查找按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        find_btn = UIUtils.create_button("查找重复文件")
        layout.addWidget(find_btn)

        self.duplicate_find_btn = find_btn

        return find_btn, layout

    def create_duplicate_progress_bar(self) -> QProgressBar:
        """
        创建进度条

        Returns:
            QProgressBar: 进度条
        """
        if not PYQT_AVAILABLE:
            return None

        progress_bar = UIUtils.create_progress_bar()
        self.duplicate_progress_bar = progress_bar

        return progress_bar

    def create_duplicate_files_table(self) -> QTableWidget:
        """
        创建重复文件表格

        Returns:
            QTableWidget: 重复文件表格
        """
        if not PYQT_AVAILABLE:
            return None

        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["文件名", "大小", "修改时间", "路径", "选择"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSortingEnabled(True)

        self.duplicate_files_table = table

        return table

    def create_duplicate_operations(self) -> tuple:
        """
        创建操作区域

        Returns:
            tuple: (取消选择按钮, 删除选中按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        deselect_btn = UIUtils.create_button("取消选择")
        delete_btn = UIUtils.create_button("删除选中文件")

        layout.addWidget(deselect_btn)
        layout.addWidget(delete_btn)

        self.deselect_all_btn = deselect_btn
        self.delete_selected_btn = delete_btn

        return deselect_btn, delete_btn, layout

    def create_help_label(self) -> QLabel:
        """
        创建帮助标签

        Returns:
            QLabel: 帮助标签
        """
        if not PYQT_AVAILABLE:
            return None

        label = QLabel("提示：选中要删除的文件，然后点击删除按钮")
        label.setStyleSheet(UIStyles.HELP_LABEL_STYLE)

        self.duplicate_help_label = label

        return label

    def set_folder(self, path: str) -> None:
        """
        设置文件夹路径

        Args:
            path: 文件夹路径
        """
        if self.duplicate_folder_edit:
            self.duplicate_folder_edit.setText(path)

    def get_folder(self) -> str:
        """
        获取文件夹路径

        Returns:
            str: 文件夹路径
        """
        if self.duplicate_folder_edit:
            return self.duplicate_folder_edit.text().strip()
        return ""

    def set_buttons_enabled(self, enabled: bool) -> None:
        """
        设置按钮启用状态

        Args:
            enabled: 是否启用
        """
        if self.duplicate_find_btn:
            self.duplicate_find_btn.setEnabled(enabled)

    def update_progress(self, value: int) -> None:
        """
        更新进度

        Args:
            value: 进度值 (0-100)
        """
        if self.duplicate_progress_bar:
            self.duplicate_progress_bar.setValue(value)

    def clear_table(self) -> None:
        """清空表格"""
        if self.duplicate_files_table:
            self.duplicate_files_table.setRowCount(0)

    def display_duplicate_files(self, duplicate_groups: List[Dict[str, Any]]) -> None:
        """
        显示重复文件

        Args:
            duplicate_groups: 重复文件组列表
        """
        if not self.duplicate_files_table:
            return

        self.duplicate_files_table.setRowCount(0)

        row = 0
        for group in duplicate_groups:
            size = group.get('size', 0)
            files = group.get('files', [])

            for file_info in files:
                file_path = file_info.get('path', '')
                file_name = os.path.basename(file_path)
                modified_time = file_info.get('modified_time', 0)

                self.duplicate_files_table.insertRow(row)

                name_item = FileTableWidgetItem(file_name)
                self.duplicate_files_table.setItem(row, 0, name_item)

                size_str = UIUtils.format_file_size(size)
                size_item = FileTableWidgetItem(size_str, file_size=size)
                self.duplicate_files_table.setItem(row, 1, size_item)

                time_str = UIUtils.format_timestamp(modified_time)
                time_item = FileTableWidgetItem(time_str, file_time=modified_time)
                self.duplicate_files_table.setItem(row, 2, time_item)

                self.duplicate_files_table.setItem(row, 3, QTableWidgetItem(file_path))

                checkbox = QCheckBox()
                checkbox.setChecked(False)
                self.duplicate_files_table.setCellWidget(row, 4, checkbox)

                row += 1

    def get_selected_files(self) -> List[str]:
        """
        获取选中的文件

        Returns:
            List[str]: 选中文件的路径列表
        """
        if not self.duplicate_files_table:
            return []

        selected_files = []
        for row in range(self.duplicate_files_table.rowCount()):
            checkbox = self.duplicate_files_table.cellWidget(row, 4)
            if checkbox and checkbox.isChecked():
                path_item = self.duplicate_files_table.item(row, 3)
                if path_item:
                    selected_files.append(path_item.text())

        return selected_files

    def deselect_all(self) -> None:
        """取消所有选择"""
        if not self.duplicate_files_table:
            return

        for row in range(self.duplicate_files_table.rowCount()):
            checkbox = self.duplicate_files_table.cellWidget(row, 4)
            if checkbox:
                checkbox.setChecked(False)
