#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用UI组件和样式常量
用于文件夹管理工具（Myfile）
"""

from typing import Optional, List, Dict, Any, Callable
import os
import logging

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
        QLabel, QLineEdit, QPushButton, QComboBox, QProgressBar, 
        QTextEdit, QFileDialog, QCheckBox, QMessageBox, QSplitter,
        QFrame, QGroupBox, QGridLayout, QTreeView, QTabWidget,
        QHeaderView, QMenu, QRadioButton, QTableWidget, QTableWidgetItem,
        QAbstractItemView, QSizePolicy
    )
    from PyQt6.QtGui import QAction, QIcon, QFont, QColor, QPalette, QTextCursor
    from PyQt6.QtCore import (
        QObject as QtQObject, QThread as QtThread, pyqtSignal as qtSignal, 
        pyqtSlot, QDir as QtDDir, QSortFilterProxyModel as QtSortFilterProxyModel, 
        QTimer as QtTimer, Qt as QtQt
    )
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


class UIStyles:
    """UI样式常量类"""

    BUTTON_HEIGHT = 35
    BUTTON_WIDTH = 80
    INPUT_HEIGHT = 35
    MIN_BUTTON_HEIGHT = 30
    PROGRESS_HEIGHT = 30
    LOG_HEIGHT = 200

    BUTTON_STYLE = """
        QPushButton { 
            border-radius: 3px; 
            padding: 5px 0px; 
            margin: 0px; 
            min-height: 35px;
            max-height: 35px;
            height: 35px;
        }
    """

    LOG_BACKGROUND_COLOR = QColor(245, 245, 245)
    LOG_TEXT_COLOR = QColor(0, 0, 0)

    HELP_LABEL_STYLE = "color: #666; font-style: italic;"

    LOG_FONT_FAMILY = "Consolas"
    LOG_FONT_SIZE = 9

    TABLE_COLUMN_WIDTH_NAME = 0
    TABLE_COLUMN_WIDTH_SIZE = 100
    TABLE_COLUMN_WIDTH_TYPE = 100
    TABLE_COLUMN_WIDTH_MODIFIED = 150

    LAYOUT_MARGIN = 5
    LAYOUT_SPACING = 5

    TREEVIEW_COLUMN_NAME = "名称"
    TREEVIEW_COLUMN_SIZE = "大小"
    TREEVIEW_COLUMN_TYPE = "类型"
    TREEVIEW_COLUMN_MODIFIED = "修改日期"


class UIUtils:
    """UI工具类"""

    @staticmethod
    def get_log_palette() -> Optional[QPalette]:
        """
        获取日志区域的调色板

        Returns:
            Optional[QPalette]: 日志调色板，如果PyQt不可用则返回None
        """
        if not PYQT_AVAILABLE:
            return None
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Base, UIStyles.LOG_BACKGROUND_COLOR)
        palette.setColor(QPalette.ColorRole.Text, UIStyles.LOG_TEXT_COLOR)
        return palette

    @staticmethod
    def get_log_font() -> Optional[QFont]:
        """
        获取日志区域的字体

        Returns:
            Optional[QFont]: 日志字体，如果PyQt不可用则返回None
        """
        if not PYQT_AVAILABLE:
            return None
        return QFont(UIStyles.LOG_FONT_FAMILY, UIStyles.LOG_FONT_SIZE)

    @staticmethod
    def create_button(text: str, min_height: int = UIStyles.MIN_BUTTON_HEIGHT, 
                     fixed_width: Optional[int] = None, 
                     fixed_height: Optional[int] = None) -> QPushButton:
        """
        创建标准按钮

        Args:
            text: 按钮文本
            min_height: 最小高度
            fixed_width: 固定宽度（可选）
            fixed_height: 固定高度（可选）

        Returns:
            QPushButton: 创建的按钮
        """
        if not PYQT_AVAILABLE:
            return None
        btn = QPushButton(text)
        btn.setMinimumHeight(min_height)
        if fixed_width is not None:
            btn.setFixedWidth(fixed_width)
        if fixed_height is not None:
            btn.setFixedHeight(fixed_height)
        return btn

    @staticmethod
    def create_browse_button(callback: Callable, fixed_width: int = UIStyles.BUTTON_WIDTH,
                           fixed_height: int = UIStyles.BUTTON_HEIGHT) -> QPushButton:
        """
        创建浏览按钮

        Args:
            callback: 点击回调函数
            fixed_width: 固定宽度
            fixed_height: 固定高度

        Returns:
            QPushButton: 创建的浏览按钮
        """
        if not PYQT_AVAILABLE:
            return None
        btn = QPushButton("浏览...")
        btn.setFixedWidth(fixed_width)
        btn.setFixedHeight(fixed_height)
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn.setStyleSheet(UIStyles.BUTTON_STYLE)
        btn.clicked.connect(callback)
        return btn

    @staticmethod
    def create_line_edit(placeholder: str = "", fixed_height: int = UIStyles.INPUT_HEIGHT,
                       min_width: Optional[int] = None) -> QLineEdit:
        """
        创建单行输入框

        Args:
            placeholder: 占位符文本
            fixed_height: 固定高度
            min_width: 最小宽度（可选）

        Returns:
            QLineEdit: 创建的输入框
        """
        if not PYQT_AVAILABLE:
            return None
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        edit.setFixedHeight(fixed_height)
        if min_width is not None:
            edit.setMinimumWidth(min_width)
        return edit

    @staticmethod
    def create_progress_bar() -> QProgressBar:
        """
        创建进度条

        Returns:
            QProgressBar: 创建的进度条
        """
        if not PYQT_AVAILABLE:
            return None
        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(0)
        progress.setTextVisible(True)
        return progress

    @staticmethod
    def create_log_text_edit(read_only: bool = True) -> QTextEdit:
        """
        创建日志文本编辑框

        Args:
            read_only: 是否只读

        Returns:
            QTextEdit: 创建的文本编辑框
        """
        if not PYQT_AVAILABLE:
            return None
        text_edit = QTextEdit()
        text_edit.setReadOnly(read_only)
        text_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text_edit.setUndoRedoEnabled(False)
        text_edit.setPalette(UIUtils.get_log_palette())
        text_edit.setFont(UIUtils.get_log_font())
        return text_edit

    @staticmethod
    def create_table_widget(column_count: int, headers: List[str]) -> QTableWidget:
        """
        创建表格组件

        Args:
            column_count: 列数
            headers: 列头列表

        Returns:
            QTableWidget: 创建的表格
        """
        if not PYQT_AVAILABLE:
            return None
        table = QTableWidget()
        table.setColumnCount(column_count)
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        return table

    @staticmethod
    def format_file_size(size: int) -> str:
        """
        格式化文件大小

        Args:
            size: 文件大小（字节）

        Returns:
            str: 格式化后的文件大小字符串
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    @staticmethod
    def format_timestamp(timestamp: float) -> str:
        """
        格式化时间戳

        Args:
            timestamp: Unix时间戳

        Returns:
            str: 格式化后的时间字符串
        """
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def show_error(parent: QWidget, title: str, message: str) -> None:
        """
        显示错误对话框

        Args:
            parent: 父窗口
            title: 标题
            message: 消息内容
        """
        if not PYQT_AVAILABLE:
            return
        QMessageBox.critical(parent, title, message)

    @staticmethod
    def show_info(parent: QWidget, title: str, message: str) -> None:
        """
        显示信息对话框

        Args:
            parent: 父窗口
            title: 标题
            message: 消息内容
        """
        if not PYQT_AVAILABLE:
            return
        QMessageBox.information(parent, title, message)

    @staticmethod
    def show_warning(parent: QWidget, title: str, message: str) -> None:
        """
        显示警告对话框

        Args:
            parent: 父窗口
            title: 标题
            message: 消息内容
        """
        if not PYQT_AVAILABLE:
            return
        QMessageBox.warning(parent, title, message)

    @staticmethod
    def ask_confirmation(parent: QWidget, title: str, message: str) -> bool:
        """
        显示确认对话框

        Args:
            parent: 父窗口
            title: 标题
            message: 消息内容

        Returns:
            bool: 用户是否确认
        """
        if not PYQT_AVAILABLE:
            return True
        reply = QMessageBox.question(
            parent, title, message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        return reply == QMessageBox.StandardButton.Yes

    @staticmethod
    def create_folder_group(title: str, layout: Any) -> QGroupBox:
        """
        创建文件夹选择组

        Args:
            title: 组标题
            layout: 布局对象

        Returns:
            QGroupBox: 创建的组
        """
        if not PYQT_AVAILABLE:
            return None
        group = QGroupBox(title)
        group.setLayout(layout)
        layout.setContentsMargins(UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN, 
                                UIStyles.LAYOUT_MARGIN, UIStyles.LAYOUT_MARGIN)
        layout.setSpacing(UIStyles.LAYOUT_SPACING)
        return group

    @staticmethod
    def create_tree_view() -> QTreeView:
        """
        创建树形视图

        Returns:
            QTreeView: 创建的树形视图
        """
        if not PYQT_AVAILABLE:
            return None
        tree = QTreeView()
        tree.setRootIsDecorated(True)
        tree.setSortingEnabled(True)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        tree.header().setSectionResizeMode(UIStyles.TABLE_COLUMN_WIDTH_NAME, QHeaderView.ResizeMode.Stretch)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_SIZE, UIStyles.TABLE_COLUMN_WIDTH_SIZE)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_TYPE, UIStyles.TABLE_COLUMN_WIDTH_TYPE)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_MODIFIED, UIStyles.TABLE_COLUMN_WIDTH_MODIFIED)
        return tree

    @staticmethod
    def setup_file_system_model(tree: QTreeView, model: Any) -> None:
        """
        设置文件系统模型

        Args:
            tree: 树形视图
            model: 文件系统模型
        """
        if not PYQT_AVAILABLE:
            return
        tree.setModel(model)
        tree.setRootIsDecorated(True)
        tree.setSortingEnabled(True)
        tree.header().setSectionResizeMode(UIStyles.TABLE_COLUMN_WIDTH_NAME, QHeaderView.ResizeMode.Stretch)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_SIZE, UIStyles.TABLE_COLUMN_WIDTH_SIZE)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_TYPE, UIStyles.TABLE_COLUMN_WIDTH_TYPE)
        tree.setColumnWidth(UIStyles.TABLE_COLUMN_WIDTH_MODIFIED, UIStyles.TABLE_COLUMN_WIDTH_MODIFIED)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

    @staticmethod
    def create_chinese_header_proxy_model() -> Optional[Any]:
        """
        创建中文表头代理模型

        Returns:
            Optional[Any]: 代理模型，如果PyQt不可用则返回None
        """
        if not PYQT_AVAILABLE:
            return None
        try:
            from PyQt6.QtCore import QSortFilterProxyModel
            class ChineseHeaderProxyModel(QSortFilterProxyModel):
                def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                    if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                        if section == 0:
                            return UIStyles.TREEVIEW_COLUMN_NAME
                        elif section == 1:
                            return UIStyles.TREEVIEW_COLUMN_SIZE
                        elif section == 2:
                            return UIStyles.TREEVIEW_COLUMN_TYPE
                        elif section == 3:
                            return UIStyles.TREEVIEW_COLUMN_MODIFIED
                    return super().headerData(section, orientation, role)
            return ChineseHeaderProxyModel()
        except ImportError:
            return None

    @staticmethod
    def browse_directory(parent: QWidget, title: str = "选择文件夹", 
                        start_dir: str = "") -> Optional[str]:
        """
        浏览文件夹

        Args:
            parent: 父窗口
            title: 对话框标题
            start_dir: 起始目录

        Returns:
            Optional[str]: 选择的文件夹路径，取消则返回None
        """
        if not PYQT_AVAILABLE:
            return None
        folder = QFileDialog.getExistingDirectory(parent, title, start_dir)
        return folder if folder else None


class FileTableWidgetItem(QTableWidgetItem):
    """文件表格项，支持按大小和日期排序"""

    def __init__(self, text: str, file_size: int = 0, file_time: float = 0):
        """
        初始化文件表格项

        Args:
            text: 显示文本
            file_size: 文件大小（用于排序）
            file_time: 文件时间（用于排序）
        """
        super().__init__(text)
        self.file_size = file_size
        self.file_time = file_time
        self.setData(QtQt.ItemDataRole.UserRole, file_size)

    def __lt__(self, other: 'FileTableWidgetItem') -> bool:
        """
        比较运算符，用于排序

        Args:
            other: 另一个表格项

        Returns:
            bool: 是否小于
        """
        if hasattr(other, 'file_size'):
            return self.file_size < other.file_size
        return self.text() < other.text()
