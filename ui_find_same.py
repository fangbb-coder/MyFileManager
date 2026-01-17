#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
相同文件比对UI模块
用于文件夹管理工具（Myfile）
"""

from typing import Optional, Any, List, Tuple
import os

try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
        QPushButton, QProgressBar, QGroupBox, QSplitter, 
        QTreeView, QTableWidget, QTableWidgetItem, 
        QHeaderView, QAbstractItemView, QSizePolicy
    )
    from PyQt6.QtCore import Qt, QDir, QSortFilterProxyModel
    from PyQt6.QtGui import QTextCursor
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

from ui_components import UIStyles, UIUtils


class FindSameUI:
    """相同文件比对UI类"""

    def __init__(self, parent: Any):
        """
        初始化相同文件比对UI

        Args:
            parent: 父窗口或主应用实例
        """
        self.parent = parent
        self._init_ui_components()

    def _init_ui_components(self) -> None:
        """初始化UI组件"""
        if not PYQT_AVAILABLE:
            return

        self.find_same_folder_a_edit = None
        self.find_same_folder_b_edit = None
        self.find_same_ignore_edit = None
        self.find_same_source_tree = None
        self.find_same_target_tree = None
        self.find_same_source_model = None
        self.find_same_target_model = None
        self.find_same_files_btn = None
        self.find_same_progress_bar = None
        self.find_same_log_text = None
        self.find_same_files_table = None
        self.delete_selected_a_button = None
        self.delete_selected_b_button = None

    def create_find_same_folder_selector(self, title: str, callback: Any) -> tuple:
        """
        创建文件夹选择器

        Args:
            title: 组标题
            callback: 浏览按钮回调函数

        Returns:
            tuple: (输入框, 浏览按钮, 组)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        group = QGroupBox(title)
        layout = QHBoxLayout(group)
        layout.setContentsMargins(UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN,
                                UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN)
        layout.setSpacing(UIStyles.LAYOUT_SPACING)

        edit = QLineEdit()
        edit.setFixedHeight(UIStyles.INPUT_HEIGHT)
        edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        browse_btn = UIUtils.create_browse_button(callback)

        layout.addWidget(edit, 1)
        layout.addWidget(browse_btn)

        layout.setAlignment(edit, Qt.AlignmentFlag.AlignVCenter)
        layout.setAlignment(browse_btn, Qt.AlignmentFlag.AlignVCenter)

        return edit, browse_btn, group

    def create_find_same_options_group(self) -> QGroupBox:
        """
        创建查找选项组

        Returns:
            QGroupBox: 查找选项组
        """
        if not PYQT_AVAILABLE:
            return None

        group = QGroupBox("查找选项")
        layout = QHBoxLayout(group)
        layout.setContentsMargins(UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN,
                                UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN)
        layout.setSpacing(UIStyles.LAYOUT_SPACING)

        label = QLabel("忽略文件：")
        edit = QLineEdit()
        edit.setPlaceholderText("例如: *.tmp, *.bak")
        edit.setMinimumWidth(200)
        edit.setFixedHeight(UIStyles.INPUT_HEIGHT)

        layout.addWidget(label)
        layout.addWidget(edit)

        self.find_same_ignore_edit = edit

        return group

    def create_find_same_buttons(self) -> tuple:
        """
        创建查找控制按钮

        Returns:
            tuple: (查找按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        btn = UIUtils.create_button("查找相同文件")
        layout.addWidget(btn)

        self.find_same_files_btn = btn

        return btn, layout

    def create_find_same_progress_and_log(self) -> tuple:
        """
        创建查找进度条和日志区域

        Returns:
            tuple: (进度条, 日志文本框, 分割器)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        splitter = QSplitter(Qt.Orientation.Vertical)

        progress_widget = QWidget()
        progress_layout = QVBoxLayout(progress_widget)
        progress_bar = UIUtils.create_progress_bar()
        progress_layout.addWidget(progress_bar)
        splitter.addWidget(progress_widget)

        log_group = QGroupBox("比对日志")
        log_layout = QVBoxLayout()
        log_text = UIUtils.create_log_text_edit()
        log_layout.addWidget(log_text)
        log_group.setLayout(log_layout)
        splitter.addWidget(log_group)

        splitter.setSizes([30, UIStyles.LOG_HEIGHT])

        self.find_same_progress_bar = progress_bar
        self.find_same_log_text = log_text

        return progress_bar, log_text, splitter

    def create_find_same_files_table(self) -> QTableWidget:
        """
        创建相同文件表格

        Returns:
            QTableWidget: 相同文件表格
        """
        if not PYQT_AVAILABLE:
            return None

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["文件夹A文件", "文件夹B文件", "操作", "批量操作"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.find_same_files_table = table

        return table

    def create_batch_operations(self) -> tuple:
        """
        创建批量操作区域

        Returns:
            tuple: (删除A按钮, 删除B按钮, 布局)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        delete_a_btn = UIUtils.create_button("删除选中文件夹A文件")
        delete_b_btn = UIUtils.create_button("删除选中文件夹B文件")

        layout.addWidget(delete_a_btn)
        layout.addWidget(delete_b_btn)

        self.delete_selected_a_button = delete_a_btn
        self.delete_selected_b_button = delete_b_btn

        return delete_a_btn, delete_b_btn, layout

    def setup_file_trees(self, source_tree: QTreeView, target_tree: QTreeView,
                        source_model: Any, target_model: Any) -> None:
        """
        设置文件树

        Args:
            source_tree: 源文件树
            target_tree: 目标文件树
            source_model: 源文件模型
            target_model: 目标文件模型
        """
        if not PYQT_AVAILABLE:
            return

        self.find_same_source_tree = source_tree
        self.find_same_target_tree = target_tree
        self.find_same_source_model = source_model
        self.find_same_target_model = target_model

        UIUtils.setup_file_system_model(source_tree, source_model)
        UIUtils.setup_file_system_model(target_tree, target_model)

    def set_folder_a(self, path: str) -> None:
        """
        设置文件夹A路径

        Args:
            path: 文件夹路径
        """
        if self.find_same_folder_a_edit:
            self.find_same_folder_a_edit.setText(path)

    def set_folder_b(self, path: str) -> None:
        """
        设置文件夹B路径

        Args:
            path: 文件夹路径
        """
        if self.find_same_folder_b_edit:
            self.find_same_folder_b_edit.setText(path)

    def get_folder_a(self) -> str:
        """
        获取文件夹A路径

        Returns:
            str: 文件夹路径
        """
        if self.find_same_folder_a_edit:
            return self.find_same_folder_a_edit.text().strip()
        return ""

    def get_folder_b(self) -> str:
        """
        获取文件夹B路径

        Returns:
            str: 文件夹路径
        """
        if self.find_same_folder_b_edit:
            return self.find_same_folder_b_edit.text().strip()
        return ""

    def get_ignore_patterns(self) -> str:
        """
        获取忽略模式

        Returns:
            str: 忽略模式字符串
        """
        if self.find_same_ignore_edit:
            return self.find_same_ignore_edit.text().strip()
        return ""

    def set_buttons_enabled(self, enabled: bool) -> None:
        """
        设置按钮启用状态

        Args:
            enabled: 是否启用
        """
        if self.find_same_files_btn:
            self.find_same_files_btn.setEnabled(enabled)

    def update_progress(self, value: int) -> None:
        """
        更新进度

        Args:
            value: 进度值 (0-100)
        """
        if self.find_same_progress_bar:
            self.find_same_progress_bar.setValue(value)

    def append_log(self, message: str) -> None:
        """
        添加日志消息

        Args:
            message: 日志消息
        """
        if self.find_same_log_text:
            self.find_same_log_text.append(message)
            self.find_same_log_text.moveCursor(QTextCursor.MoveOperation.End)

    def clear_log(self) -> None:
        """清空日志"""
        if self.find_same_log_text:
            self.find_same_log_text.clear()

    def clear_table(self) -> None:
        """清空表格"""
        if self.find_same_files_table:
            self.find_same_files_table.setRowCount(0)

    def display_same_files(self, same_files: List[Tuple[str, str]]) -> None:
        """
        显示相同文件

        Args:
            same_files: 相同文件列表，每个元素是 (file_a, file_b) 元组
        """
        if not self.find_same_files_table:
            return

        self.find_same_files_table.setRowCount(0)

        for i, (file_a, file_b) in enumerate(same_files):
            self.find_same_files_table.insertRow(i)

            self.find_same_files_table.setItem(i, 0, QTableWidgetItem(file_a))
            self.find_same_files_table.setItem(i, 1, QTableWidgetItem(file_b))

    def get_selected_rows(self) -> List[int]:
        """
        获取选中的行

        Returns:
            List[int]: 选中行的索引列表
        """
        if not self.find_same_files_table:
            return []

        selected_items = self.find_same_files_table.selectedItems()
        if not selected_items:
            return []

        rows = set()
        for item in selected_items:
            rows.add(item.row())

        return sorted(list(rows))
