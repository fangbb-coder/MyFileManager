#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
同步功能UI模块
用于文件夹管理工具（Myfile）
"""

from typing import Optional, Any, List
import os

try:
    from PyQt6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
        QPushButton, QComboBox, QProgressBar, QTextEdit, 
        QCheckBox, QGroupBox, QSplitter, QTreeView, 
        QHeaderView, QAbstractItemView, QSizePolicy
    )
    from PyQt6.QtCore import Qt, QDir, QSortFilterProxyModel
    from PyQt6.QtGui import QTextCursor
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

from ui_components import UIStyles, UIUtils


class SyncUI:
    """同步功能UI类"""

    def __init__(self, parent: Any):
        """
        初始化同步UI

        Args:
            parent: 父窗口或主应用实例
        """
        self.parent = parent
        self._init_ui_components()

    def _init_ui_components(self) -> None:
        """初始化UI组件"""
        if not PYQT_AVAILABLE:
            return

        self.sync_folder_a_edit = None
        self.sync_folder_b_edit = None
        self.sync_browse_a_btn = None
        self.sync_browse_b_btn = None
        self.sync_source_tree = None
        self.sync_target_tree = None
        self.sync_source_model = None
        self.sync_target_model = None
        self.sync_mode_combo = None
        self.sync_ignore_edit = None
        self.sync_delete_checkbox = None
        self.only_show_diff_files = None
        self.start_btn = None
        self.pause_btn = None
        self.stop_btn = None
        self.sync_progress_bar = None
        self.sync_log_text = None

    def create_sync_folder_selector(self, title: str, callback: Any) -> tuple:
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

    def create_sync_options_group(self) -> QGroupBox:
        """
        创建同步选项组

        Returns:
            QGroupBox: 同步选项组
        """
        if not PYQT_AVAILABLE:
            return None

        group = QGroupBox("同步选项")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN,
                                UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN)
        layout.setSpacing(UIStyles.LAYOUT_SPACING)

        mode_layout = QHBoxLayout()
        mode_label = QLabel("同步模式：")
        mode_combo = QComboBox()
        mode_combo.addItems(["A → B (单向)", "B → A (单向)", "A ↔ B (双向)"])
        mode_combo.setFixedHeight(UIStyles.INPUT_HEIGHT)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(mode_combo)
        layout.addLayout(mode_layout)

        ignore_layout = QHBoxLayout()
        ignore_label = QLabel("忽略文件：")
        ignore_edit = QLineEdit()
        ignore_edit.setPlaceholderText("例如: *.tmp, *.bak")
        ignore_edit.setMinimumWidth(200)
        ignore_edit.setFixedHeight(UIStyles.INPUT_HEIGHT)
        ignore_layout.addWidget(ignore_label)
        ignore_layout.addWidget(ignore_edit)
        layout.addLayout(ignore_layout)

        options_layout = QHBoxLayout()
        delete_label = QLabel("同步删除：")
        delete_checkbox = QCheckBox()
        delete_label.setFixedWidth(70)
        options_layout.addWidget(delete_label)
        options_layout.addWidget(delete_checkbox)

        show_label = QLabel("只显示不同的文件：")
        show_checkbox = QCheckBox()
        show_label.setFixedWidth(70)
        options_layout.addWidget(show_label)
        options_layout.addWidget(show_checkbox)
        layout.addLayout(options_layout)

        self.sync_mode_combo = mode_combo
        self.sync_ignore_edit = ignore_edit
        self.sync_delete_checkbox = delete_checkbox
        self.only_show_diff_files = show_checkbox

        return group

    def create_sync_buttons(self) -> tuple:
        """
        创建同步控制按钮

        Returns:
            tuple: (开始按钮, 暂停按钮, 停止按钮)
        """
        if not PYQT_AVAILABLE:
            return None, None, None

        layout = QHBoxLayout()
        layout.setSpacing(10)

        start_btn = UIUtils.create_button("开始同步")
        pause_btn = UIUtils.create_button("暂停")
        stop_btn = UIUtils.create_button("停止")

        pause_btn.setEnabled(False)
        stop_btn.setEnabled(False)

        layout.addWidget(start_btn)
        layout.addWidget(pause_btn)
        layout.addWidget(stop_btn)

        self.start_btn = start_btn
        self.pause_btn = pause_btn
        self.stop_btn = stop_btn

        return start_btn, pause_btn, stop_btn, layout

    def create_sync_progress_and_log(self) -> tuple:
        """
        创建同步进度条和日志区域

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

        log_group = QGroupBox("同步日志")
        log_layout = QVBoxLayout()
        log_text = UIUtils.create_log_text_edit()
        log_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        log_layout.addWidget(log_text)
        log_group.setLayout(log_layout)
        splitter.addWidget(log_group)

        splitter.setSizes([30, UIStyles.LOG_HEIGHT])

        self.sync_progress_bar = progress_bar
        self.sync_log_text = log_text

        return progress_bar, log_text, splitter

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

        self.sync_source_tree = source_tree
        self.sync_target_tree = target_tree
        self.sync_source_model = source_model
        self.sync_target_model = target_model

        UIUtils.setup_file_system_model(source_tree, source_model)
        UIUtils.setup_file_system_model(target_tree, target_model)

    def set_folder_a(self, path: str) -> None:
        """
        设置文件夹A路径

        Args:
            path: 文件夹路径
        """
        if self.sync_folder_a_edit:
            self.sync_folder_a_edit.setText(path)

    def set_folder_b(self, path: str) -> None:
        """
        设置文件夹B路径

        Args:
            path: 文件夹路径
        """
        if self.sync_folder_b_edit:
            self.sync_folder_b_edit.setText(path)

    def get_folder_a(self) -> str:
        """
        获取文件夹A路径

        Returns:
            str: 文件夹路径
        """
        if self.sync_folder_a_edit:
            return self.sync_folder_a_edit.text().strip()
        return ""

    def get_folder_b(self) -> str:
        """
        获取文件夹B路径

        Returns:
            str: 文件夹路径
        """
        if self.sync_folder_b_edit:
            return self.sync_folder_b_edit.text().strip()
        return ""

    def get_sync_mode(self) -> str:
        """
        获取同步模式

        Returns:
            str: 同步模式
        """
        if self.sync_mode_combo:
            mode_text = self.sync_mode_combo.currentText()
            if mode_text == "A → B (单向)":
                return "a_to_b"
            elif mode_text == "B → A (单向)":
                return "b_to_a"
            else:
                return "two_way"
        return "a_to_b"

    def get_ignore_patterns(self) -> str:
        """
        获取忽略模式

        Returns:
            str: 忽略模式字符串
        """
        if self.sync_ignore_edit:
            return self.sync_ignore_edit.text().strip()
        return ""

    def get_sync_delete(self) -> bool:
        """
        获取是否同步删除

        Returns:
            bool: 是否同步删除
        """
        if self.sync_delete_checkbox:
            return self.sync_delete_checkbox.isChecked()
        return False

    def get_only_show_diff(self) -> bool:
        """
        获取是否只显示不同文件

        Returns:
            bool: 是否只显示不同文件
        """
        if self.only_show_diff_files:
            return self.only_show_diff_files.isChecked()
        return False

    def set_buttons_enabled(self, enabled: bool) -> None:
        """
        设置按钮启用状态

        Args:
            enabled: 是否启用
        """
        if self.start_btn:
            self.start_btn.setEnabled(enabled)
        if self.pause_btn:
            self.pause_btn.setEnabled(not enabled)
        if self.stop_btn:
            self.stop_btn.setEnabled(not enabled)

    def update_progress(self, value: int) -> None:
        """
        更新进度

        Args:
            value: 进度值 (0-100)
        """
        if self.sync_progress_bar:
            self.sync_progress_bar.setValue(value)

    def append_log(self, message: str) -> None:
        """
        添加日志消息

        Args:
            message: 日志消息
        """
        if self.sync_log_text:
            self.sync_log_text.append(message)
            self.sync_log_text.moveCursor(QTextCursor.MoveOperation.End)

    def clear_log(self) -> None:
        """清空日志"""
        if self.sync_log_text:
            self.sync_log_text.clear()
