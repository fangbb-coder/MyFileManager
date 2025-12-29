#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
界面逻辑模块
用于文件夹管理工具（Myfile）
"""

import os
import sys
import threading
import logging
from datetime import datetime
import hashlib
import concurrent.futures
from collections import defaultdict
from utils import copy_file

# 尝试导入 PyQt6，如果失败则尝试 Tkinter
PYQT_AVAILABLE = False
QThread = None
pyqtSignal = None
QFileSystemModel = None
QObject = None
Qt = None
QDir = None
QSortFilterProxyModel = None
QTimer = None
QApplication = None
QMainWindow = None
QWidget = None
QVBoxLayout = None
QHBoxLayout = None
QLabel = None
QLineEdit = None
QPushButton = None
QComboBox = None
QProgressBar = None
QTextEdit = None
QFileDialog = None
QCheckBox = None
QMessageBox = None
QSplitter = None
QFrame = None
QGroupBox = None
QGridLayout = None
QTreeView = None
QTabWidget = None
QHeaderView = None
QMenu = None
QRadioButton = None
QTableWidget = None
QTableWidgetItem = None
QAbstractItemView = None
QSizePolicy = None
QAction = None
QIcon = None
QFont = None
QColor = None
QPalette = None
QTextCursor = None

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
    
    # 尝试从多个可能的位置导入QFileSystemModel
    try:
        from PyQt6.QtWidgets import QFileSystemModel
        QFileSystemModel = QFileSystemModel
    except ImportError:
        try:
            from PyQt6.QtCore import QFileSystemModel
            QFileSystemModel = QFileSystemModel
        except ImportError:
            try:
                from PyQt6.QtGui import QFileSystemModel
                QFileSystemModel = QFileSystemModel
            except ImportError:
                # 如果都导入失败，则使用替代方案
                print("QFileSystemModel导入失败，将使用替代实现")
                
    # 为兼容性设置别名
    QObject = QtQObject
    QThread = QtThread
    pyqtSignal = qtSignal
    QDir = QtDDir
    QSortFilterProxyModel = QtSortFilterProxyModel
    QTimer = QtTimer
    Qt = QtQt
    
    PYQT_AVAILABLE = True
    print("PyQt6 导入成功！")
except ImportError as e:
    print(f"PyQt6 导入失败: {str(e)}")
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, scrolledtext
        print("Tkinter 导入成功")
    except ImportError:
        print("Tkinter 也未安装，请安装 PyQt6 或 Tkinter")
        sys.exit(1)

# 定义条件类继承的基类
BaseThread = threading.Thread
if PYQT_AVAILABLE and QThread is not None:
    BaseThread = QThread

# 定义条件信号类
ConditionalSignal = None
if PYQT_AVAILABLE and pyqtSignal is not None:
    ConditionalSignal = pyqtSignal
else:
    # 在非PyQt模式下，创建一个空的信号类
    class DummySignal:
        def __init__(self, *args):
            pass
        
        def emit(self, *args):
            pass
    
    ConditionalSignal = DummySignal

# 定义条件基类
BaseObject = object
if PYQT_AVAILABLE and QObject is not None:
    BaseObject = QObject

# 自定义 QTableWidgetItem 类，用于按字节数值排序
if PYQT_AVAILABLE and QTableWidgetItem is not None:
    class SizeTableWidgetItem(QTableWidgetItem):
        def __init__(self, text, size_bytes):
            super().__init__(text)
            self.size_bytes = size_bytes
        
        def __lt__(self, other):
            if other is None:
                return True
            try:
                return self.size_bytes < other.size_bytes
            except AttributeError:
                return super().__lt__(other)
    
    class CountTableWidgetItem(QTableWidgetItem):
        def __init__(self, text, count):
            super().__init__(text)
            self.count = count
        
        def __lt__(self, other):
            if other is None:
                return True
            try:
                return self.count < other.count
            except AttributeError:
                return super().__lt__(other)
else:
    SizeTableWidgetItem = None
    CountTableWidgetItem = None

class FileSlimmingThread(BaseThread):
    """文件夹搜身线程 - 扫描大文件"""
    
    # 定义信号
    progress_updated = ConditionalSignal(int)
    current_file_updated = ConditionalSignal(str)
    result_ready = ConditionalSignal(list)
    log_updated = ConditionalSignal(str)
    
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # 初始为非暂停状态
    
    def stop(self):
        """停止扫描"""
        self._stop_event.set()
        self._pause_event.set()  # 确保线程可以退出
        if PYQT_AVAILABLE:
            self.wait()
    
    def pause(self):
        """暂停扫描"""
        self._pause_event.clear()
    
    def resume(self):
        """恢复扫描"""
        self._pause_event.set()
    
    def _emit_log(self, message):
        """发送日志信息"""
        if PYQT_AVAILABLE:
            self.log_updated.emit(message)
    
    def _emit_progress(self, progress):
        """发送进度更新"""
        if PYQT_AVAILABLE:
            self.progress_updated.emit(progress)
    
    def _emit_current_file(self, file_path):
        """发送当前处理的文件"""
        if PYQT_AVAILABLE:
            self.current_file_updated.emit(file_path)
    
    def _emit_results(self, file_list):
        """发送扫描结果"""
        if PYQT_AVAILABLE:
            self.result_ready.emit(file_list)
    
    def run(self):
        """执行文件扫描"""
        try:
            self._emit_log(f"开始扫描文件夹: {self.directory}")
            file_list = []
            total_files = 0
            scanned_files = 0
            
            # 首先计算总文件数
            for root_dir, _, files in os.walk(self.directory):
                # 检查是否取消扫描
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return
                
                # 检查是否暂停
                self._pause_event.wait()
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return
                
                total_files += len(files)
            
            # 再次遍历收集文件信息
            for root_dir, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return
                
                # 检查是否暂停
                self._pause_event.wait()
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return
                
                for file in files:
                    if self._stop_event.is_set():
                        self._emit_log("扫描已取消")
                        return
                    
                    # 检查是否暂停
                    self._pause_event.wait()
                    if self._stop_event.is_set():
                        self._emit_log("扫描已取消")
                        return
                    
                    file_path = os.path.join(root_dir, file)
                    try:
                        # 获取文件信息
                        file_stats = os.stat(file_path)
                        file_size = file_stats.st_size
                        modified_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        
                        # 添加到列表
                        file_list.append({
                            "name": file,
                            "path": root_dir,
                            "size": file_size,
                            "modified": modified_time,
                            "full_path": file_path
                        })
                        
                        # 更新当前文件
                        self._emit_current_file(file_path)
                        
                    except (FileNotFoundError, PermissionError) as e:
                        # 忽略无法访问的文件
                        self._emit_log(f"无法访问文件: {file_path}, 错误: {str(e)}")
                    except Exception as e:
                        self._emit_log(f"处理文件时出错: {file_path}, 错误: {str(e)}")
                    
                    # 更新进度
                    scanned_files += 1
                    progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
                    self._emit_progress(int(progress))
            
            # 按文件大小排序（从大到小）
            file_list.sort(key=lambda x: x["size"], reverse=True)
            
            # 只取前100个大文件
            top_files = file_list[:100]
            
            if not self._stop_event.is_set():
                self._emit_log(f"扫描完成，共找到 {len(file_list)} 个文件，显示前100个大文件")
                self._emit_results(top_files)
        
        except Exception as e:
            self._emit_log(f"扫描过程中发生错误: {str(e)}")


class DuplicateFinderThread(BaseThread):
    """重复文件查找线程"""
    
    # 配置常量
    THREADS = 4  # 线程池大小
    HASH_ALGO = "md5"  # 使用的哈希算法
    CHUNK_SIZE = 8192  # 读取文件块大小
    
    progress_updated = ConditionalSignal(int)
    log_updated = ConditionalSignal(str)
    duplicate_files_found = ConditionalSignal(list)
    current_file_updated = ConditionalSignal(str)
    
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self._stop_event = threading.Event()
        self._total_files = 0
        self._processed_files = 0
        self._hash_processed_files = 0
        self._hash_total_files = 0
    
    def stop(self):
        """停止扫描"""
        self._stop_event.set()
        if PYQT_AVAILABLE:
            self.wait()
    
    def _emit_log(self, message):
        """发送日志信息"""
        if PYQT_AVAILABLE:
            self.log_updated.emit(message)
    
    def _emit_progress(self, progress):
        """发送进度更新"""
        if PYQT_AVAILABLE:
            self.progress_updated.emit(progress)
    
    def _emit_current_file(self, file_path):
        """发送当前处理的文件"""
        if PYQT_AVAILABLE:
            self.current_file_updated.emit(file_path)
    
    def _emit_results(self, duplicate_groups):
        """发送扫描结果"""
        if PYQT_AVAILABLE:
            self.duplicate_files_found.emit(duplicate_groups)
            
    def _file_hash(self, path, algo="md5", chunk_size=8192):
        """计算文件哈希值"""
        h = getattr(hashlib, algo)()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    if self._stop_event.is_set():
                        return None
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None
        except Exception as e:
            self._emit_log(f"计算文件哈希时出错 {path}: {str(e)}")
            return None
            
    def _update_hash_progress(self):
        """更新哈希计算的进度"""
        if self._hash_total_files > 0:
            # 第一阶段扫描占50%，哈希计算占50%
            scan_progress = 50
            hash_progress = int((self._hash_processed_files / self._hash_total_files) * 50)
            total_progress = scan_progress + hash_progress
            self._emit_progress(total_progress)
    
    def run(self):
        """执行重复文件扫描，基于文件大小和哈希值"""
        try:
            self._emit_log(f"开始扫描目录: {self.directory}")
            
            # 统计总文件数
            self._total_files = 0
            for root, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    return
                self._total_files += len(files)
            
            self._emit_log(f"找到 {self._total_files} 个文件，开始按大小分组...")
            
            # 收集所有文件（按大小分组）
            size_groups = defaultdict(list)
            self._processed_files = 0
            
            # 第一阶段：扫描文件并按大小分组（占50%进度）
            for root, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    return
                
                for filename in files:
                    if self._stop_event.is_set():
                        return
                    
                    file_path = os.path.join(root, filename)
                    try:
                        # 跳过目录和无法访问的文件
                        if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
                            continue
                        
                        # 获取文件大小
                        file_size = os.path.getsize(file_path)
                        # 跳过空文件
                        if file_size == 0:
                            continue
                        
                        # 获取文件修改时间
                        file_modified_time = os.path.getmtime(file_path)
                        
                        # 按大小分组
                        size_groups[file_size].append({
                            'path': file_path,
                            'size': file_size,
                            'modified_time': file_modified_time
                        })
                        
                        # 更新进度（第一阶段占50%）
                        self._processed_files += 1
                        progress = int((self._processed_files / self._total_files) * 50)
                        self._emit_progress(progress)
                        self._emit_current_file(file_path)
                        
                    except Exception as e:
                        self._emit_log(f"处理文件 {file_path} 时出错: {str(e)}")
            
            # 完成第一阶段
            self._emit_log("文件扫描完成，开始计算可能重复文件的哈希值...")
            
            # 第二阶段：对大小相同的文件组计算哈希值（占50%进度）
            # 统计需要计算哈希的文件数量
            self._hash_total_files = 0
            for size, files in size_groups.items():
                if len(files) > 1:  # 只有数量大于1的组才需要计算哈希
                    self._hash_total_files += len(files)
            
            if self._hash_total_files == 0:
                # 没有可能的重复文件
                self._emit_progress(100)
                self._emit_log("未找到重复文件")
                self._emit_results([])
                return
            
            self._hash_processed_files = 0
            hash_groups = defaultdict(list)
            
            # 使用线程池并行计算哈希
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS) as executor:
                for size, files in size_groups.items():
                    if self._stop_event.is_set():
                        break
                    
                    if len(files) < 2:
                        continue
                    
                    # 为当前大小组的所有文件提交哈希计算任务
                    future_to_file = {}
                    for file_info in files:
                        file_path = file_info['path']
                        future = executor.submit(self._file_hash, file_path, self.HASH_ALGO, self.CHUNK_SIZE)
                        future_to_file[future] = file_info
                    
                    # 处理完成的任务
                    for future in concurrent.futures.as_completed(future_to_file):
                        if self._stop_event.is_set():
                            break
                        
                        file_info = future_to_file[future]
                        file_path = file_info['path']
                        
                        try:
                            file_hash = future.result()
                            if file_hash:
                                hash_groups[file_hash].append(file_info)
                        except Exception as e:
                            self._emit_log(f"处理文件哈希时出错 {file_path}: {str(e)}")
                        finally:
                            # 更新进度
                            self._hash_processed_files += 1
                            self._update_hash_progress()
                            self._emit_current_file(file_path)
            
            # 提取重复文件组（哈希值相同且数量大于1的）
            duplicate_groups = []
            for file_hash, files in hash_groups.items():
                if len(files) > 1:
                    # 使用第一个文件的大小作为组大小
                    group_size = files[0]['size'] if files else 0
                    duplicate_groups.append({
                        'size': group_size,
                        'hash': file_hash,  # 新增哈希值信息
                        'files': files
                    })
            
            # 发送100%进度
            self._emit_progress(100)
            self._emit_log(f"扫描完成，找到 {len(duplicate_groups)} 组重复文件（基于大小和内容哈希值）")
            self._emit_results(duplicate_groups)
            
        except Exception as e:
            self._emit_log(f"扫描过程中出错: {str(e)}")


class FolderSizeThread(BaseThread):
    """文件夹大小计算线程"""
    
    progress_updated = ConditionalSignal(int)
    log_updated = ConditionalSignal(str)
    result_ready = ConditionalSignal(list)
    current_folder_updated = ConditionalSignal(str)
    
    def __init__(self, directory, sync_engine, ignore_patterns=None):
        super().__init__()
        self.directory = directory
        self.sync_engine = sync_engine
        self.ignore_patterns = ignore_patterns
        self._stop_event = threading.Event()
    
    def stop(self):
        """停止扫描"""
        self._stop_event.set()
        if PYQT_AVAILABLE:
            self.wait()
    
    def _emit_log(self, message):
        """发送日志信息"""
        if PYQT_AVAILABLE:
            self.log_updated.emit(message)
    
    def _emit_progress(self, progress):
        """发送进度更新"""
        if PYQT_AVAILABLE:
            self.progress_updated.emit(progress)
    
    def _emit_current_folder(self, folder_path):
        """发送当前处理的文件夹"""
        if PYQT_AVAILABLE:
            self.current_folder_updated.emit(folder_path)
    
    def _emit_results(self, folder_list):
        """发送扫描结果"""
        if PYQT_AVAILABLE:
            self.result_ready.emit(folder_list)
    
    def run(self):
        """执行文件夹大小计算"""
        try:
            self._emit_log(f"开始计算文件夹大小: {self.directory}")
            
            if not os.path.exists(self.directory):
                self._emit_log(f"目录不存在: {self.directory}")
                self._emit_results([])
                return
            
            folder_sizes = []
            
            # 只获取根目录的直接子文件夹
            try:
                entries = os.listdir(self.directory)
            except PermissionError:
                self._emit_log(f"无法访问目录: {self.directory}")
                self._emit_results([])
                return
            
            subfolders = []
            for entry in entries:
                entry_path = os.path.join(self.directory, entry)
                if os.path.isdir(entry_path):
                    subfolders.append(entry_path)
            
            total_folders = len(subfolders)
            processed_folders = 0
            
            # 计算每个子文件夹的大小
            for folder_path in subfolders:
                if self._stop_event.is_set():
                    self._emit_log("计算已取消")
                    return
                
                # 更新当前文件夹
                self._emit_current_folder(folder_path)
                
                # 计算文件夹总大小（包括所有子文件夹和文件）
                folder_size = 0
                file_count = 0
                
                for root, dirs, files in os.walk(folder_path):
                    if self._stop_event.is_set():
                        break
                    
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        try:
                            file_size = os.path.getsize(file_path)
                            folder_size += file_size
                            file_count += 1
                        except (FileNotFoundError, PermissionError):
                            pass
                
                # 获取文件夹信息
                folder_name = os.path.basename(folder_path)
                folder_modified_time = os.path.getmtime(folder_path)
                
                # 添加到列表
                folder_sizes.append({
                    "name": folder_name,
                    "path": folder_path,
                    "size": folder_size,
                    "file_count": file_count,
                    "modified_time": folder_modified_time,
                    "modified": datetime.fromtimestamp(folder_modified_time).strftime('%Y-%m-%d %H:%M:%S')
                })
                
                # 更新进度
                processed_folders += 1
                progress = (processed_folders / total_folders) * 100 if total_folders > 0 else 0
                self._emit_progress(int(progress))
            
            # 按文件夹大小排序（从大到小）
            folder_sizes.sort(key=lambda x: x["size"], reverse=True)
            
            if not self._stop_event.is_set():
                self._emit_log(f"计算完成，共找到 {len(folder_sizes)} 个子文件夹")
                self._emit_results(folder_sizes)
        
        except Exception as e:
            self._emit_log(f"计算过程中发生错误: {str(e)}")


class CopyFilesThread(BaseThread):
    """用于复制文件的线程，使用信号通知主线程刷新UI"""
    copy_finished = ConditionalSignal(int, int)  # 复制完成(copied_count, failed_count)
    refresh_needed = ConditionalSignal()  # 需要刷新
    
    def __init__(self, ui_instance, selected_indices, direction, model, source_model, use_proxy, source_dir, target_dir):
        super().__init__()
        self.ui = ui_instance
        self.selected_indices = list(selected_indices)  # 创建副本
        self.direction = direction
        self.model = model
        self.source_model = source_model
        self.use_proxy = use_proxy
        self.source_dir = source_dir
        self.target_dir = target_dir
    
    def run(self):
        """Execute file copying in background thread"""
        copied_count = 0
        failed_count = 0
        verified_count = 0
        verify_failed_count = 0
        
        try:
            for index in self.selected_indices:
                try:
                    # 如果使用代理模型，需要转换索引
                    if self.use_proxy:
                        source_index = self.model.mapToSource(index)
                        if not source_index.isValid():
                            self.ui._log_message(f"无效的索引转换", source="sync")
                            failed_count += 1
                            continue
                        file_path = self.source_model.filePath(source_index)
                    else:
                        file_path = self.source_model.filePath(index)
                    
                    if not os.path.exists(file_path):
                        self.ui._log_message(f"源文件不存在: {file_path}", source="sync")
                        failed_count += 1
                        continue
                    
                    try:
                        rel_path = os.path.relpath(file_path, self.source_dir)
                    except ValueError:
                        rel_path = os.path.basename(file_path)
                    
                    dest_path = os.path.join(self.target_dir, rel_path)
                    
                    if os.path.normpath(file_path) == os.path.normpath(dest_path):
                        self.ui._log_message(f"源文件和目标文件相同: {file_path}", source="sync")
                        continue
                    
                    dest_dir_parent = os.path.dirname(dest_path)
                    if not os.path.exists(dest_dir_parent):
                        try:
                            os.makedirs(dest_dir_parent, exist_ok=True)
                        except Exception as e:
                            self.ui._log_message(f"创建目标目录失败: {str(e)}", source="sync")
                            failed_count += 1
                            continue
                    
                    import shutil
                    try:
                        if os.path.isdir(file_path):
                            if os.path.exists(dest_path):
                                self.ui._log_message(f"目标目录已存在: {dest_path}", source="sync")
                                failed_count += 1
                                continue
                            shutil.copytree(file_path, dest_path)
                            self.ui._log_message(f"复制目录成功: {file_path} -> {dest_path}", source="sync")
                            copied_count += 1
                            verified_count += 1
                        else:
                            shutil.copy2(file_path, dest_path)
                            self.ui._log_message(f"复制文件成功: {file_path} -> {dest_path}", source="sync")
                            
                            # 验证复制
                            try:
                                source_stat = os.stat(file_path)
                                dest_stat = os.stat(dest_path)
                                
                                if source_stat.st_size == dest_stat.st_size:
                                    import hashlib
                                    def get_file_md5(filepath):
                                        hash_md5 = hashlib.md5()
                                        with open(filepath, "rb") as f:
                                            for chunk in iter(lambda: f.read(4096), b""):
                                                hash_md5.update(chunk)
                                        return hash_md5.hexdigest()
                                    
                                    source_md5 = get_file_md5(file_path)
                                    dest_md5 = get_file_md5(dest_path)
                                    
                                    if source_md5 == dest_md5:
                                        verified_count += 1
                                        self.ui._log_message(f"文件复制验证成功: {dest_path}", source="sync")
                                    else:
                                        verify_failed_count += 1
                                        self.ui._log_message(f"文件复制验证失败（MD5不匹配）: {dest_path}", source="sync")
                                else:
                                    verify_failed_count += 1
                                    self.ui._log_message(f"文件复制验证失败（大小不匹配）: {dest_path}", source="sync")
                            except Exception as verify_e:
                                verify_failed_count += 1
                                self.ui._log_message(f"文件验证时出错: {str(verify_e)}", source="sync")
                            
                            copied_count += 1
                    except Exception as e:
                        self.ui._log_message(f"复制失败: {str(e)}", source="sync")
                        failed_count += 1
                except Exception as e:
                    self.ui._log_message(f"处理文件时出错: {str(e)}", source="sync")
                    failed_count += 1
            
            # 记录结果
            self.ui._log_message(f"复制验证结果: 成功 {verified_count} 个, 验证失败 {verify_failed_count} 个", source="sync")
            result_msg = f"复制完成: 成功 {copied_count} 个, 失败 {failed_count} 个"
            self.ui._log_message(result_msg, source="sync")
            
            # 发出完成信号
            if PYQT_AVAILABLE:
                try:
                    self.copy_finished.emit(copied_count, failed_count)
                    # 等待文件系统更新
                    import time
                    time.sleep(0.5)
                    # 发出刷新信号
                    self.refresh_needed.emit()
                except Exception as signal_e:
                    self.ui._log_message(f"发出信号时出错: {str(signal_e)}", source="sync")
        except Exception as e:
            self.ui._log_message(f"复制线程运行时发生严重错误: {str(e)}", source="sync")
            import traceback
            self.ui._log_message(f"错误详情: {traceback.format_exc()}", source="sync")
            # 尝试发出完成信号，即使出错也要通知主线程
            if PYQT_AVAILABLE:
                try:
                    self.copy_finished.emit(copied_count, failed_count)
                except Exception as emit_e:
                    self.ui._log_message(f"发出完成信号时出错: {str(emit_e)}", source="sync")
                finally:
                    # 确保无论如何都尝试发出刷新信号
                    try:
                        self.refresh_needed.emit()
                    except Exception as refresh_e:
                        self.ui._log_message(f"发出刷新信号时出错: {str(refresh_e)}", source="sync")


class SyncThread(BaseThread):
    """同步任务线程类"""
    # 定义信号（PyQt模式）
    progress_updated = ConditionalSignal(int)
    log_updated = ConditionalSignal(str)
    sync_completed = ConditionalSignal(bool)

    same_files_found = ConditionalSignal(list)
    current_file_updated = ConditionalSignal(str)
    
    def __init__(self, sync_engine, dir_a, dir_b, task_type="sync", sync_mode="a_to_b", sync_delete=False, ignore_patterns=None):
        if PYQT_AVAILABLE:
            super().__init__()
        else:
            super().__init__(daemon=True)
            self.progress_callback = None

            self.log_callback = None
            self.completed_callback = None
            self.same_files_callback = None

        
        self.sync_engine = sync_engine
        self.dir_a = dir_a
        self.dir_b = dir_b
        self.task_type = task_type  # "sync" 或 "find_same"
        self.sync_mode = sync_mode
        self.sync_delete = sync_delete
        self.ignore_patterns = ignore_patterns
        self.last_log_length = 0
        self._running = False
    
    def run(self):
        """运行同步任务或查找相同文件任务"""
        print(f"[DEBUG] SyncThread.run() 开始执行, 任务类型: {self.task_type}")
        print(f"[DEBUG] 任务参数: dir_a={self.dir_a}, dir_b={self.dir_b}, ignore_patterns={self.ignore_patterns}")
        
        # 初始化日志长度
        self.last_log_length = 0
        
        # 设置为运行中
        self._running = True
        print("[DEBUG] 线程状态已设置为运行中")
        
        # 执行任务
        success = False
        same_files = []
        
        try:
            if self.task_type == "find_same":
                print("[DEBUG] 开始执行相同文件查找任务")
                # 执行相同文件查找，默认不显示重复文件
                same_files = self.sync_engine.find_same_files(
                    self.dir_a, 
                    self.dir_b, 
                    self.ignore_patterns,
                    show_duplicates=False
                )
                print(f"[DEBUG] 相同文件查找完成，找到 {len(same_files) if same_files else 0} 个相同文件")
                success = True
            else:  # task_type == "sync"
                print("[DEBUG] 开始执行同步任务")
                # 仅在同步模式下执行同步操作
                success = self.sync_engine.run_sync(
                    self.dir_a, 
                    self.dir_b, 
                    self.sync_mode, 
                    self.sync_delete, 
                    self.ignore_patterns
                )
                print(f"[DEBUG] 同步任务完成，成功: {success}")
        except Exception as e:
            import traceback
            error_source = "find_same" if self.task_type == "find_same" else "sync"
            error_msg = f"{error_source}任务执行时发生错误: {str(e)}"
            tb_str = traceback.format_exc()
            print(f"[DEBUG] {error_msg}\n{tb_str}")
            success = False
            if hasattr(self, 'ui') and hasattr(self.ui, '_log_message'):
                self.ui._log_message(error_msg, source=error_source)
                self.ui._log_message(f"错误详情: {tb_str}", source=error_source)
        
        finally:
            # 确保无论成功失败都执行到这里
            print("[DEBUG] 进入finally块")
            
            # 发送相同文件列表信号（仅针对find_same任务）
            if self.task_type == "find_same" and self._running:
                print("[DEBUG] 线程仍在运行，准备发送相同文件列表")
                try:
                    if PYQT_AVAILABLE:
                        print("[DEBUG] PyQt模式：准备发送信号")
                        self.same_files_found.emit(same_files)
                        print("[DEBUG] 相同文件信号发送成功")
                    else:
                        print("[DEBUG] Tkinter模式：准备调用回调")
                        if self.same_files_callback:
                            self.same_files_callback(same_files)
                            print("[DEBUG] 相同文件回调调用成功")
                except Exception as signal_e:
                    error_msg = f"发送相同文件信号时出错: {str(signal_e)}"
                    print(f"[DEBUG] {error_msg}")
                    if hasattr(self, 'ui') and hasattr(self.ui, '_log_message'):
                        self.ui._log_message(error_msg, source="find_same")
            
            # 停止运行
            self._running = False
            print("[DEBUG] 线程状态已设置为停止")
            
            # 最后一次更新进度和日志
            try:
                print("[DEBUG] 执行最后一次进度更新")
                self.update_progress()
                print("[DEBUG] 进度更新完成")
            except Exception as e:
                print(f"[DEBUG] 更新进度异常: {e}")
            
            # 发送完成信号
            try:
                print("[DEBUG] 准备发送完成信号")
                if PYQT_AVAILABLE:
                    print(f"[DEBUG] PyQt模式: 发送完成信号，成功状态={success}")
                    self.sync_completed.emit(success)
                else:
                    print(f"[DEBUG] Tkinter模式: 检查完成回调")
                    if self.completed_callback:
                        print(f"[DEBUG] 调用完成回调，成功状态={success}")
                        self.completed_callback(success)
                print("[DEBUG] 完成信号发送/回调调用成功")
            except Exception as e:
                print(f"[DEBUG] 发送完成信号异常: {e}")
            
            print(f"[DEBUG] SyncThread.run() 方法执行完成，任务类型: {self.task_type}")
    
    def stop(self):
        """安全停止线程"""
        print("[DEBUG] SyncThread.stop() 方法开始执行")
        try:
            # 标记为停止
            print("[DEBUG] 标记线程为停止状态")
            self._running = False
            
            # 停止同步引擎
            if hasattr(self, 'sync_engine') and self.sync_engine:
                print("[DEBUG] 同步引擎存在")
                if hasattr(self.sync_engine, 'stop'):
                    print("[DEBUG] 调用同步引擎的stop方法")
                    self.sync_engine.stop()
            
            # 在PyQt模式下，确保线程完全停止
            if PYQT_AVAILABLE and hasattr(self, 'wait'):
                print("[DEBUG] PyQt模式，等待线程结束，最多2秒")
                # 首先尝试正常等待
                if not self.wait(2000):
                    print("[DEBUG] 线程等待超时，尝试强制终止")
                    # 如果超时，尝试强制终止
                    if hasattr(self, 'terminate'):
                        try:
                            print("[DEBUG] 调用terminate()终止线程")
                            self.terminate()
                            print("[DEBUG] 等待终止操作完成，最多1秒")
                            self.wait(1000)
                            print("[DEBUG] 线程终止完成")
                        except Exception as e:
                            print(f"[DEBUG] 线程终止异常: {e}")
                else:
                    print("[DEBUG] 线程成功终止")
            else:
                print("[DEBUG] 非PyQt模式或线程没有wait方法")
                
            print("[DEBUG] SyncThread.stop() 方法执行完成")
        except Exception as e:
            print(f"[DEBUG] 停止线程异常: {e}")
    
    def update_progress(self):
        """更新进度和日志"""
        try:
            if not hasattr(self, 'sync_engine') or not self.sync_engine or not self._running:
                return
            
            progress = self.sync_engine.get_progress()
            # 获取当前正在处理的文件
            current_file = ""
            if hasattr(self.sync_engine, '_current_file'):
                current_file = self.sync_engine._current_file
            
            if PYQT_AVAILABLE:
                # 发送进度更新信号
                try:
                    if hasattr(self, 'progress_updated'):
                        self.progress_updated.emit(progress)
                except Exception as e:
                    pass  # 忽略信号发送错误
                
                # 发送当前文件更新信号
                if current_file and hasattr(self, 'current_file_updated'):
                    try:
                        self.current_file_updated.emit(current_file)
                    except Exception as e:
                        pass  # 忽略信号发送错误
            else:
                # Tkinter模式回调
                if hasattr(self, 'progress_callback') and self.progress_callback:
                    try:
                        self.progress_callback(progress)
                    except Exception as e:
                        pass  # 忽略回调错误
                # 调用当前文件回调
                if current_file and hasattr(self, 'current_file_callback') and self.current_file_callback:
                    try:
                        self.current_file_callback(current_file)
                    except Exception as e:
                        pass  # 忽略回调错误
        except Exception as e:
            pass  # 忽略所有错误，确保方法不会崩溃
        
        # 更新日志 - 确保捕获所有新日志
        try:
            if hasattr(self, 'sync_engine') and self.sync_engine:
                logs = self.sync_engine.get_log()
                if logs and len(logs) > self.last_log_length:
                    new_logs = logs[self.last_log_length:]
                    for log in new_logs:
                        try:
                            # 确保使用正确的日志源
                            source = "find_same" if self.task_type == "find_same" else "sync"
                            if PYQT_AVAILABLE and hasattr(self, 'log_updated'):
                                # 传递任务类型信息
                                self.log_updated.emit(log)
                            elif hasattr(self, 'log_callback') and self.log_callback:
                                # 直接调用带源参数的回调
                                if source == "find_same":
                                    self.log_callback(log, source="find_same")
                                else:
                                    self.log_callback(log)
                        except Exception as e:
                            print(f"[DEBUG] 日志更新错误: {e}")
                            pass  # 忽略单个日志更新错误
                    self.last_log_length = len(logs)
        except Exception as e:
            print(f"[DEBUG] 日志更新块错误: {e}")
            pass  # 忽略日志更新错误


class SyncApp(BaseObject):
    """
    文件同步应用类
    """
    
    def eventFilter(self, watched, event):
        """实现事件过滤器方法，处理窗口事件
        
        Args:
            watched: 被监视的对象
            event: 事件对象
            
        Returns:
            bool: 是否拦截事件
        """
        # 这里简单地传递事件，不做特殊处理
        # 如果需要处理特定事件，可以在这里添加逻辑
        return False
    
    def __init__(self):
        if PYQT_AVAILABLE:
            super().__init__()
        # 初始化日志记录器
        self.logger = logging.getLogger(__name__)
        self.sync_engine = None  # 同步引擎实例将在主程序中设置
        self.sync_thread = None
        self.running = False  # 任务运行状态标志
        
        if PYQT_AVAILABLE:
            self._init_pyqt_ui()
        else:
            self._init_tkinter_ui()
    
    def _init_pyqt_ui(self):
        """使用PyQt6初始化界面"""
        # 导入必要的模块
        from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                                    QTabWidget, QGroupBox, QLineEdit, QPushButton, QCheckBox, QTreeView, 
                                    QHeaderView, QAbstractItemView, QLabel, QSplitter, QSizePolicy)
        from PyQt6.QtCore import Qt, QDir, QSortFilterProxyModel, QTimer
        from PyQt6.QtGui import QFont, QIcon
        
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("文件夹管理工具 - Myfile")
        self.app.setStyle("Fusion")
        
        # 设置应用程序图标
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smart_file_icon.png")
        if os.path.exists(icon_path):
            self.app.setWindowIcon(QIcon(icon_path))
        
        # 设置中文字体
        font = QFont()
        font.setFamily("微软雅黑")
        font.setPointSize(9)
        self.app.setFont(font)
        
        # 创建主窗口
        self.window = QMainWindow()
        self.window.setWindowTitle("文件夹管理工具 - Myfile")
        self.window.setMinimumSize(1200, 700)
        
        # 自动比对定时器（用于手动输入路径时的防抖处理）
        self.auto_compare_timer = QTimer()
        self.auto_compare_timer.setSingleShot(True)
        self.auto_compare_timer.setInterval(600)
        self.auto_compare_timer.timeout.connect(lambda: self._auto_compare_if_ready(force=False))
        
        # 相同文件比对防抖定时器
        self.find_same_timer = QTimer()
        self.find_same_timer.setSingleShot(True)
        self.find_same_timer.setInterval(800)  # 比同步页面稍长，避免频繁触发
        self.find_same_timer.timeout.connect(self._find_same_files_if_ready)
        
        # 设置窗口图标
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smart_file_icon.png")
        if os.path.exists(icon_path):
            self.window.setWindowIcon(QIcon(icon_path))
        
        # 创建中心部件
        central_widget = QWidget()
        self.window.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # ===== 使用TabWidget分离功能 =====
        self.tab_widget = QTabWidget()
        
        # 同步页面
        self.sync_tab = QWidget()
        self.sync_tab_layout = QVBoxLayout(self.sync_tab)
        
        # 相同文件比对页面
        self.find_same_tab = QWidget()
        self.find_same_tab_layout = QVBoxLayout(self.find_same_tab)
        
        # 重复文件查找页面
        self.find_duplicate_tab = QWidget()
        # 不在这里重新创建布局，而是在下方定义时使用这个widget
        
        # 文件夹搜身页面
        self.file_slimming_tab = QWidget()
        
        # 文件夹大小页面
        self.folder_size_tab = QWidget()
        
        # 添加Tab到TabWidget
        self.tab_widget.addTab(self.sync_tab, "文件夹同步")
        self.tab_widget.addTab(self.find_same_tab, "相同文件比对")
        self.tab_widget.addTab(self.find_duplicate_tab, "重复文件查找")
        self.tab_widget.addTab(self.file_slimming_tab, "文件夹搜身")
        self.tab_widget.addTab(self.folder_size_tab, "文件夹大小")
        self.tab_widget.currentChanged.connect(self._tab_changed)
        
        # ===== 同步页面 - 文件夹选择和内容显示区域（左右结构）=====
        sync_folder_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 左侧：源文件夹
        sync_left_panel = QWidget()
        sync_left_layout = QVBoxLayout(sync_left_panel)
        
        # 源文件夹选择
        sync_left_folder_group = QGroupBox("源文件夹 A")
        sync_left_folder_layout = QHBoxLayout()
        # 设置布局边距和间距
        sync_left_folder_layout.setContentsMargins(5, 5, 5, 5)
        sync_left_folder_layout.setSpacing(5)
        sync_left_folder_group.setLayout(sync_left_folder_layout)
        
        self.sync_folder_a_edit = QLineEdit()
        self.sync_folder_a_edit.setFixedHeight(35)  # 直接设置固定高度
        self.sync_folder_a_edit.setText("")  # 确保默认为空
        if PYQT_AVAILABLE:
            self.sync_folder_a_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)  # 水平扩展，垂直固定
        sync_left_folder_layout.addWidget(self.sync_folder_a_edit, 1)
        self.sync_folder_a_edit.textChanged.connect(lambda _: self._on_sync_folder_text_changed("A"))
        
        self.sync_browse_a_btn = QPushButton("浏览...")
        self.sync_browse_a_btn.setFixedWidth(80)  # 固定宽度
        self.sync_browse_a_btn.setFixedHeight(35)  # 与输入框相同高度
        # 确保按钮与文本框基线对齐
        if PYQT_AVAILABLE:
            self.sync_browse_a_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)  # 固定大小
        # 更精确的样式表，确保高度一致
        self.sync_browse_a_btn.setStyleSheet("""
            QPushButton { 
                border-radius: 3px; 
                padding: 5px 0px; 
                margin: 0px; 
                min-height: 35px;
                max-height: 35px;
                height: 35px;
            }
        """)  # 添加内边距控制
        self.sync_browse_a_btn.clicked.connect(self._browse_folder_a)
        sync_left_folder_layout.addWidget(self.sync_browse_a_btn)
        
        # 确保左侧文件夹选择组件高度一致
        sync_left_folder_layout.setAlignment(self.sync_folder_a_edit, Qt.AlignmentFlag.AlignVCenter)
        sync_left_folder_layout.setAlignment(self.sync_browse_a_btn, Qt.AlignmentFlag.AlignVCenter)
        
        sync_left_layout.addWidget(sync_left_folder_group)
        
        # 这部分已经移到同步选项组中
        
        # 源文件夹内容显示
        self.sync_source_tree = QTreeView()
        if QFileSystemModel is not None:
            self.sync_source_model = QFileSystemModel()
            self.sync_source_model.setRootPath('')
            self.sync_source_model.setReadOnly(True)
            self.sync_source_model.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDot)
            
            # 设置中文列名（必须在setRootPath之后）
            # self.sync_source_model.setHeaderData(0, Qt.Orientation.Horizontal, "名称")
            # self.sync_source_model.setHeaderData(1, Qt.Orientation.Horizontal, "大小")
            # self.sync_source_model.setHeaderData(2, Qt.Orientation.Horizontal, "类型")
            # self.sync_source_model.setHeaderData(3, Qt.Orientation.Horizontal, "修改日期")
            
            self.sync_source_tree.setModel(self.sync_source_model)
            self.sync_source_tree.setRootIsDecorated(True)
            self.sync_source_tree.setSortingEnabled(True)
            
            # 使用代理模型显示中文列名
            if PYQT_AVAILABLE:
                try:
                    from PyQt6.QtCore import QSortFilterProxyModel
                    class ChineseHeaderProxyModel(QSortFilterProxyModel):
                        def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                            if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                                if section == 0:
                                    return "名称"
                                elif section == 1:
                                    return "大小"
                                elif section == 2:
                                    return "类型"
                                elif section == 3:
                                    return "修改日期"
                            return super().headerData(section, orientation, role)
                    
                    # 应用代理模型
                    proxy_model = ChineseHeaderProxyModel()
                    proxy_model.setSourceModel(self.sync_source_model)
                    self.sync_source_tree.setModel(proxy_model)
                except ImportError:
                    # 如果导入失败，直接使用原模型
                    pass
            
            # 直接设置表头中文显示
            # header = self.sync_source_tree.header()
            # self.sync_source_tree.model().setHeaderData(0, Qt.Orientation.Horizontal, "名称")
            # self.sync_source_tree.model().setHeaderData(1, Qt.Orientation.Horizontal, "大小")
            # self.sync_source_tree.model().setHeaderData(2, Qt.Orientation.Horizontal, "类型")
            # self.sync_source_tree.model().setHeaderData(3, Qt.Orientation.Horizontal, "修改日期")
            
            # 调整列宽和显示的列
            self.sync_source_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.sync_source_tree.setColumnWidth(1, 100)
            self.sync_source_tree.setColumnWidth(2, 100)
            self.sync_source_tree.setColumnWidth(3, 150)
            
            # 启用多选功能
            self.sync_source_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            
            # 添加右键菜单
            self.sync_source_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.sync_source_tree.customContextMenuRequested.connect(lambda pos: self._show_source_context_menu(pos, tab="sync"))
            
            # 确保默认显示"我的电脑"（所有驱动器）- 不设置根索引或设置为无效索引
            from PyQt6.QtCore import QModelIndex
            self.sync_source_tree.setRootIndex(QModelIndex())  # 设置为无效索引，显示"我的电脑"
        else:
            # 如果没有QFileSystemModel，使用简单的标签提示
            placeholder_label = QLabel("文件预览功能当前不可用")
            placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sync_left_layout.addWidget(placeholder_label)
            
        sync_left_layout.addWidget(self.sync_source_tree, 1)
        
        # 右侧：目标文件夹和同步模式
        sync_right_panel = QWidget()
        sync_right_layout = QVBoxLayout(sync_right_panel)
        
        # 目标文件夹选择
        sync_right_folder_group = QGroupBox("目标文件夹 B")
        sync_right_folder_layout = QHBoxLayout()
        # 设置与左侧完全相同的布局边距和间距
        sync_right_folder_layout.setContentsMargins(5, 5, 5, 5)
        sync_right_folder_layout.setSpacing(5)
        sync_right_folder_group.setLayout(sync_right_folder_layout)
        
        self.sync_folder_b_edit = QLineEdit()
        self.sync_folder_b_edit.setFixedHeight(35)  # 直接设置固定高度
        self.sync_folder_b_edit.setText("")  # 确保默认为空
        if PYQT_AVAILABLE:
            self.sync_folder_b_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)  # 水平扩展，垂直固定
        sync_right_folder_layout.addWidget(self.sync_folder_b_edit, 1)
        self.sync_folder_b_edit.textChanged.connect(lambda _: self._on_sync_folder_text_changed("B"))
        
        self.sync_browse_b_btn = QPushButton("浏览...")
        self.sync_browse_b_btn.setFixedWidth(80)  # 固定宽度
        self.sync_browse_b_btn.setFixedHeight(35)  # 与输入框相同高度
        # 确保按钮与文本框基线对齐，并应用与左侧相同的样式
        if PYQT_AVAILABLE:
            self.sync_browse_b_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)  # 固定大小
        # 更精确的样式表，确保高度一致
        self.sync_browse_b_btn.setStyleSheet("""
            QPushButton { 
                border-radius: 3px; 
                padding: 5px 0px; 
                margin: 0px; 
                min-height: 35px;
                max-height: 35px;
                height: 35px;
            }
        """)  # 添加内边距控制
        self.sync_browse_b_btn.clicked.connect(self._browse_folder_b)
        sync_right_folder_layout.addWidget(self.sync_browse_b_btn)
        
        # 确保右侧文件夹选择组件高度一致
        sync_right_folder_layout.setAlignment(self.sync_folder_b_edit, Qt.AlignmentFlag.AlignVCenter)
        sync_right_folder_layout.setAlignment(self.sync_browse_b_btn, Qt.AlignmentFlag.AlignVCenter)
        
        sync_right_layout.addWidget(sync_right_folder_group)
        
        # 移除同步模式，将在同步选项区域中实现左右两栏布局
        
        # 目标文件夹内容显示
        self.sync_target_tree = QTreeView()
        if QFileSystemModel is not None:
            self.sync_target_model = QFileSystemModel()
            self.sync_target_model.setRootPath('')
            self.sync_target_model.setReadOnly(True)
            self.sync_target_model.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDot)
            
            # 设置中文列名（必须在setRootPath之后）
            # self.sync_target_model.setHeaderData(0, Qt.Orientation.Horizontal, "名称")
            # self.sync_target_model.setHeaderData(1, Qt.Orientation.Horizontal, "大小")
            # self.sync_target_model.setHeaderData(2, Qt.Orientation.Horizontal, "类型")
            # self.sync_target_model.setHeaderData(3, Qt.Orientation.Horizontal, "修改日期")
            
            self.sync_target_tree.setModel(self.sync_target_model)
            self.sync_target_tree.setRootIsDecorated(True)
            self.sync_target_tree.setSortingEnabled(True)
            
            # 使用代理模型显示中文列名
            if PYQT_AVAILABLE:
                try:
                    from PyQt6.QtCore import QSortFilterProxyModel
                    class ChineseHeaderProxyModel(QSortFilterProxyModel):
                        def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                            if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                                if section == 0:
                                    return "名称"
                                elif section == 1:
                                    return "大小"
                                elif section == 2:
                                    return "类型"
                                elif section == 3:
                                    return "修改日期"
                            return super().headerData(section, orientation, role)
                    
                    # 应用代理模型
                    proxy_model = ChineseHeaderProxyModel()
                    proxy_model.setSourceModel(self.sync_target_model)
                    self.sync_target_tree.setModel(proxy_model)
                except ImportError:
                    # 如果导入失败，直接使用原模型
                    pass
            
            # 直接设置表头中文显示
            # header = self.sync_target_tree.header()
            # self.sync_target_tree.model().setHeaderData(0, Qt.Orientation.Horizontal, "名称")
            # self.sync_target_tree.model().setHeaderData(1, Qt.Orientation.Horizontal, "大小")
            # self.sync_target_tree.model().setHeaderData(2, Qt.Orientation.Horizontal, "类型")
            # self.sync_target_tree.model().setHeaderData(3, Qt.Orientation.Horizontal, "修改日期")
            
            # 调整列宽和显示的列
            self.sync_target_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.sync_target_tree.setColumnWidth(1, 100)
            self.sync_target_tree.setColumnWidth(2, 100)
            self.sync_target_tree.setColumnWidth(3, 150)
            
            # 启用多选功能
            self.sync_target_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            
            # 添加右键菜单
            self.sync_target_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.sync_target_tree.customContextMenuRequested.connect(lambda pos: self._show_target_context_menu(pos, tab="sync"))
            
            # 确保默认显示"我的电脑"（所有驱动器）- 不设置根索引或设置为无效索引
            from PyQt6.QtCore import QModelIndex
            self.sync_target_tree.setRootIndex(QModelIndex())  # 设置为无效索引，显示"我的电脑"
        else:
            # 如果没有QFileSystemModel，使用简单的标签提示
            placeholder_label = QLabel("文件预览功能当前不可用")
            placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sync_right_layout.addWidget(placeholder_label)
            
        sync_right_layout.addWidget(self.sync_target_tree, 1)
        
        # 添加到分割器
        sync_folder_splitter.addWidget(sync_left_panel)
        sync_folder_splitter.addWidget(sync_right_panel)
        sync_folder_splitter.setSizes([500, 500])  # 初始大小
        
        self.sync_tab_layout.addWidget(sync_folder_splitter, 1)  # 占据主要空间
        
        # 在初始化完成后多次调用同步高度，确保正确对齐
        def initial_sync_sequence():
            # 初始同步
            self._sync_tree_heights()
            # 多次延迟同步，确保完全对齐
            for delay in [100, 300, 500, 1000]:
                QTimer.singleShot(delay, self._sync_tree_heights)
        
        # 初始延迟后启动同步序列
        QTimer.singleShot(0, initial_sync_sequence)

        # 基于资源管理器选中项初始化左右文件树
        QTimer.singleShot(0, self._init_with_explorer_selection)
        
        # 连接窗口的显示和调整大小信号
        if hasattr(self.window, 'show'):
            # 在每次显示时同步高度
            original_show = self.window.show
            def custom_show():
                original_show()
                QTimer.singleShot(0, lambda: (QApplication.processEvents(), self._sync_tree_heights()))
            self.window.show = custom_show
        
        # 处理窗口状态改变和大小调整事件
        def handle_window_adjustment():
            # 立即处理一次
            QApplication.processEvents()
            
            # 立即同步一次
            self._sync_tree_heights()
            
            # 延迟后多次调用，确保窗口调整完成后高度正确同步
            # 增加更多时间点，覆盖不同系统响应时间
            for delay in [50, 100, 200, 300, 500, 800, 1000]:
                QTimer.singleShot(delay, self._sync_tree_heights)
        
        # 连接窗口状态改变信号（处理最大化等情况）
        if hasattr(self.window, 'windowStateChanged'):
            self.window.windowStateChanged.connect(handle_window_adjustment)
        
        # 连接窗口大小调整信号
        if hasattr(self.window, 'resizeEvent'):
            original_resize = self.window.resizeEvent
            def custom_resize(event):
                original_resize(event)
                QTimer.singleShot(0, handle_window_adjustment)
            self.window.resizeEvent = custom_resize
        
        # ===== 相同文件比对页面 - 文件夹选择和内容显示区域（左右结构）=====
        find_same_folder_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 左侧：文件夹 A
        find_same_left_panel = QWidget()
        find_same_left_layout = QVBoxLayout(find_same_left_panel)
        
        # 文件夹选择
        find_same_left_folder_group = QGroupBox("文件夹 A")
        find_same_left_folder_layout = QHBoxLayout()
        find_same_left_folder_group.setLayout(find_same_left_folder_layout)
        
        self.find_same_folder_a_edit = QLineEdit()
        self.find_same_folder_a_edit.setPlaceholderText("请选择或右键设置文件夹A")
        self.find_same_folder_a_edit.textChanged.connect(self._on_find_same_folder_text_changed)
        find_same_left_folder_layout.addWidget(self.find_same_folder_a_edit, 1)
        
        self.find_same_browse_a_btn = QPushButton("浏览...")
        self.find_same_browse_a_btn.clicked.connect(self._browse_folder_a)
        find_same_left_folder_layout.addWidget(self.find_same_browse_a_btn)
        
        find_same_left_layout.addWidget(find_same_left_folder_group)
        
        # 文件夹内容显示
        self.find_same_source_tree = QTreeView()
        if QFileSystemModel is not None:
            self.find_same_source_model = QFileSystemModel()
            self.find_same_source_model.setRootPath('')
            self.find_same_source_model.setReadOnly(True)
            self.find_same_source_model.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDot)
            
            self.find_same_source_tree.setModel(self.find_same_source_model)
            self.find_same_source_tree.setRootIsDecorated(True)
            self.find_same_source_tree.setSortingEnabled(True)
            
            self.find_same_source_tree.setRootIndex(self.find_same_source_model.index(''))
            
            # 使用代理模型显示中文列名
            if PYQT_AVAILABLE:
                try:
                    from PyQt6.QtCore import QSortFilterProxyModel
                    class ChineseHeaderProxyModel(QSortFilterProxyModel):
                        def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                            if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                                if section == 0:
                                    return "名称"
                                elif section == 1:
                                    return "大小"
                                elif section == 2:
                                    return "类型"
                                elif section == 3:
                                    return "修改日期"
                            return super().headerData(section, orientation, role)
                    
                    # 应用代理模型
                    proxy_model = ChineseHeaderProxyModel()
                    proxy_model.setSourceModel(self.find_same_source_model)
                    self.find_same_source_tree.setModel(proxy_model)
                except ImportError:
                    # 如果导入失败，直接使用原模型
                    pass
            
            # 调整列宽和显示的列
            self.find_same_source_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.find_same_source_tree.setColumnWidth(1, 100)
            self.find_same_source_tree.setColumnWidth(2, 100)
            self.find_same_source_tree.setColumnWidth(3, 150)
            
            # 启用多选功能
            self.find_same_source_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            
            # 添加右键菜单
            self.find_same_source_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.find_same_source_tree.customContextMenuRequested.connect(lambda pos: self._show_source_context_menu(pos, tab="find_same"))
        else:
            # 如果没有QFileSystemModel，使用简单的标签提示
            placeholder_label = QLabel("文件预览功能当前不可用")
            placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            find_same_left_layout.addWidget(placeholder_label)
            
        find_same_left_layout.addWidget(self.find_same_source_tree, 1)
        
        # 右侧：文件夹 B
        find_same_right_panel = QWidget()
        find_same_right_layout = QVBoxLayout(find_same_right_panel)
        
        # 文件夹选择
        find_same_right_folder_group = QGroupBox("文件夹 B")
        find_same_right_folder_layout = QHBoxLayout()
        find_same_right_folder_group.setLayout(find_same_right_folder_layout)
        
        self.find_same_folder_b_edit = QLineEdit()
        self.find_same_folder_b_edit.setPlaceholderText("请选择或右键设置文件夹B")
        self.find_same_folder_b_edit.textChanged.connect(self._on_find_same_folder_text_changed)
        find_same_right_folder_layout.addWidget(self.find_same_folder_b_edit, 1)
        
        self.find_same_browse_b_btn = QPushButton("浏览...")
        self.find_same_browse_b_btn.clicked.connect(self._browse_folder_b)
        find_same_right_folder_layout.addWidget(self.find_same_browse_b_btn)
        
        find_same_right_layout.addWidget(find_same_right_folder_group)
        
        # 文件夹内容显示
        self.find_same_target_tree = QTreeView()
        if QFileSystemModel is not None:
            self.find_same_target_model = QFileSystemModel()
            self.find_same_target_model.setRootPath('')
            self.find_same_target_model.setReadOnly(True)
            self.find_same_target_model.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDot)
            
            self.find_same_target_tree.setModel(self.find_same_target_model)
            self.find_same_target_tree.setRootIsDecorated(True)
            self.find_same_target_tree.setSortingEnabled(True)
            
            self.find_same_target_tree.setRootIndex(self.find_same_target_model.index(''))
            
            # 使用代理模型显示中文列名
            if PYQT_AVAILABLE:
                try:
                    from PyQt6.QtCore import QSortFilterProxyModel
                    class ChineseHeaderProxyModel(QSortFilterProxyModel):
                        def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                            """重写表头数据以显示中文列名"""
                            if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                                if section == 0:
                                    return "名称"
                                elif section == 1:
                                    return "大小"
                                elif section == 2:
                                    return "类型"
                                elif section == 3:
                                    return "修改日期"
                            return super().headerData(section, orientation, role)
                    
                    # 应用代理模型
                    proxy_model = ChineseHeaderProxyModel()
                    proxy_model.setSourceModel(self.find_same_target_model)
                    self.find_same_target_tree.setModel(proxy_model)
                except ImportError:
                    # 如果导入失败，直接使用原模型
                    pass
            
            # 调整列宽和显示的列
            self.find_same_target_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.find_same_target_tree.setColumnWidth(1, 100)
            self.find_same_target_tree.setColumnWidth(2, 100)
            self.find_same_target_tree.setColumnWidth(3, 150)
            
            # 启用多选功能
            self.find_same_target_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            
            # 添加右键菜单
            self.find_same_target_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.find_same_target_tree.customContextMenuRequested.connect(lambda pos: self._show_target_context_menu(pos, tab="find_same"))
        else:
            # 如果没有QFileSystemModel，使用简单的标签提示
            placeholder_label = QLabel("文件预览功能当前不可用")
            placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            find_same_right_layout.addWidget(placeholder_label)
            
        find_same_right_layout.addWidget(self.find_same_target_tree, 1)
        
        # 添加到分割器
        find_same_folder_splitter.addWidget(find_same_left_panel)
        find_same_folder_splitter.addWidget(find_same_right_panel)
        find_same_folder_splitter.setSizes([1800, 1800])  # 进一步增加文件树区域大小，提供更大的文件浏览显示区域
        
        self.find_same_tab_layout.addWidget(find_same_folder_splitter, 1)  # 占据主要空间
        
        # ===== 同步页面 - 同步选项区域 =====
        sync_options_group = QGroupBox("同步选项")
        sync_options_main_layout = QHBoxLayout()  # 改为水平布局
        sync_options_group.setLayout(sync_options_main_layout)
        
        # 左侧区域 - 同步模式
        left_options_widget = QWidget()
        left_options_layout = QVBoxLayout()
        left_options_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        left_options_widget.setLayout(left_options_layout)
        
        sync_mode_label = QLabel("同步模式:")
        sync_mode_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        left_options_layout.addWidget(sync_mode_label)
        
        self.sync_mode_combo = QComboBox()
        self.sync_mode_combo.addItems(["A → B (单向)", "B → A (单向)", "A ↔ B (双向)"])
        self.sync_mode_combo.setFixedHeight(35)
        left_options_layout.addWidget(self.sync_mode_combo)
        
        left_options_layout.addSpacing(20)  # 添加间距
        
        # 右侧区域 - 其他选项
        right_options_widget = QWidget()
        right_options_layout = QVBoxLayout()
        right_options_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        right_options_widget.setLayout(right_options_layout)
        
        # 忽略规则
        ignore_layout = QHBoxLayout()
        ignore_layout.addWidget(QLabel("忽略规则:"))
        self.sync_ignore_edit = QLineEdit()
        self.sync_ignore_edit.setPlaceholderText("例如: *.tmp, *.bak")
        self.sync_ignore_edit.setMinimumWidth(200)
        ignore_layout.addWidget(self.sync_ignore_edit, 1)
        right_options_layout.addLayout(ignore_layout)
        
        # 同步删除选项 - 使用布局确保与忽略规则对齐
        delete_layout = QHBoxLayout()
        delete_layout.setSpacing(0)  # 设置间距为0，与显示设置布局保持一致
        delete_layout.setContentsMargins(0, 0, 0, 0)  # 移除外边距
        delete_label = QLabel("删除设置:")
        delete_label.setFixedWidth(70)  # 设置标签固定宽度，确保与'只显示不同的文件文件夹'复选框左侧对齐
        delete_layout.addWidget(delete_label)
        self.sync_delete_check = QCheckBox("同步删除（删除目标中多余的文件）")
        delete_layout.addWidget(self.sync_delete_check, 1)
        right_options_layout.addLayout(delete_layout)
        
        # 显示设置 - 调整布局使标签与复选框紧挨着
        show_settings_layout = QHBoxLayout()
        show_settings_layout.setSpacing(0)  # 将间距设置为0，使标签和复选框完全紧贴
        show_settings_layout.setContentsMargins(0, 0, 0, 0)  # 移除外边距
        
        show_label = QLabel("显示设置:")
        show_label.setFixedWidth(70)  # 设置标签固定宽度，确保与复选框紧贴
        show_settings_layout.addWidget(show_label)
        
        self.only_show_diff_files = QCheckBox("只显示不同的文件/文件夹")
        self.only_show_diff_files.setChecked(True)  # 默认选中
        self.only_show_diff_files.stateChanged.connect(self._on_only_diff_changed)
        show_settings_layout.addWidget(self.only_show_diff_files, 1)  # 使用拉伸因子确保复选框占满剩余空间
        
        right_options_layout.addLayout(show_settings_layout)
        
        # 将左右两个区域添加到主布局
        sync_options_main_layout.addWidget(left_options_widget, 1)  # 左侧占据较小空间
        sync_options_main_layout.addWidget(right_options_widget, 2)  # 右侧占据较大空间
        
        self.sync_tab_layout.addWidget(sync_options_group)
        
        # ===== 相同文件比对页面 - 忽略规则区域 =====
        find_same_options_group = QGroupBox("比对选项")
        find_same_options_layout = QGridLayout()
        find_same_options_group.setLayout(find_same_options_layout)
        
        # 忽略规则
        find_same_options_layout.addWidget(QLabel("忽略规则:"), 0, 0)
        
        self.find_same_ignore_edit = QLineEdit()
        self.find_same_ignore_edit.setPlaceholderText("例如: *.tmp, *.bak")
        find_same_options_layout.addWidget(self.find_same_ignore_edit, 0, 1, 1, 2)
        
        self.find_same_tab_layout.addWidget(find_same_options_group)
        
        # ===== 同步页面 - 按钮区域 =====
        sync_buttons_layout = QHBoxLayout()
        sync_buttons_layout.setSpacing(10)
        
        self.start_btn = QPushButton("开始同步")
        self.start_btn.setMinimumHeight(30)
        self.start_btn.clicked.connect(self._start_sync)
        sync_buttons_layout.addWidget(self.start_btn)
        
        self.pause_btn = QPushButton("暂停")
        self.pause_btn.setMinimumHeight(30)
        self.pause_btn.clicked.connect(self._pause_sync)
        self.pause_btn.setEnabled(False)
        sync_buttons_layout.addWidget(self.pause_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setMinimumHeight(30)
        self.stop_btn.clicked.connect(self._stop_sync)
        self.stop_btn.setEnabled(False)
        sync_buttons_layout.addWidget(self.stop_btn)
        
        self.sync_tab_layout.addLayout(sync_buttons_layout)
        
        # ===== 相同文件比对页面 - 按钮区域 =====
        find_same_buttons_layout = QHBoxLayout()
        find_same_buttons_layout.setSpacing(10)
        
        self.find_same_files_btn = QPushButton("查找相同文件")
        self.find_same_files_btn.setMinimumHeight(30)
        self.find_same_files_btn.clicked.connect(self._find_same_files)
        find_same_buttons_layout.addWidget(self.find_same_files_btn)
        
        self.find_same_tab_layout.addLayout(find_same_buttons_layout)
        
        # ===== 同步页面 - 进度条和日志区域（上下结构）=====
        sync_bottom_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # 进度条
        sync_progress_widget = QWidget()
        sync_progress_layout = QVBoxLayout(sync_progress_widget)
        self.sync_progress_bar = QProgressBar()
        self.sync_progress_bar.setRange(0, 100)
        self.sync_progress_bar.setValue(0)
        self.sync_progress_bar.setTextVisible(True)
        sync_progress_layout.addWidget(self.sync_progress_bar)
        sync_bottom_splitter.addWidget(sync_progress_widget)
        
        # 日志显示区域
        sync_log_group = QGroupBox("同步日志")
        sync_log_layout = QVBoxLayout()
        sync_log_group.setLayout(sync_log_layout)
        
        self.sync_log_text = QTextEdit()
        self.sync_log_text.setReadOnly(True)
        self.sync_log_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.sync_log_text.setUndoRedoEnabled(False)
        # 添加右键菜单
        self.sync_log_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sync_log_text.customContextMenuRequested.connect(self._show_log_context_menu)
        
        # 设置日志区域的背景和文本颜色
        sync_log_palette = QPalette()
        sync_log_palette.setColor(QPalette.ColorRole.Base, QColor(245, 245, 245))
        sync_log_palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
        self.sync_log_text.setPalette(sync_log_palette)
        
        sync_log_layout.addWidget(self.sync_log_text)
        sync_bottom_splitter.addWidget(sync_log_group)
        sync_bottom_splitter.setSizes([30, 200])  # 初始大小
        
        self.sync_tab_layout.addWidget(sync_bottom_splitter)
        
        # ===== 相同文件比对页面 - 进度条和相同文件显示区域（上下结构）=====
        find_same_bottom_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # 进度条
        find_same_progress_widget = QWidget()
        find_same_progress_layout = QVBoxLayout(find_same_progress_widget)
        self.find_same_progress_bar = QProgressBar()
        self.find_same_progress_bar.setRange(0, 100)
        self.find_same_progress_bar.setValue(0)
        self.find_same_progress_bar.setTextVisible(True)
        find_same_progress_layout.addWidget(self.find_same_progress_bar)
        find_same_bottom_splitter.addWidget(find_same_progress_widget)
        
        # 相同文件显示区域 - 移到日志区域上方
        self.find_same_files_group = QGroupBox("相同文件列表")
        find_same_files_layout = QVBoxLayout(self.find_same_files_group)
        
        # 创建相同文件表格
        self.find_same_files_table = QTableWidget()
        self.find_same_files_table.setColumnCount(4)
        self.find_same_files_table.setHorizontalHeaderLabels(["文件夹A文件", "文件夹B文件", "操作", "批量操作"])
        self.find_same_files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # 批量操作区域
        batch_ops_layout = QHBoxLayout()
        self.delete_selected_a_button = QPushButton("删除选中文件夹A文件")
        self.delete_selected_a_button.clicked.connect(lambda: self._delete_selected_files(which="a"))
        
        self.delete_selected_b_button = QPushButton("删除选中文件夹B文件")
        self.delete_selected_b_button.clicked.connect(lambda: self._delete_selected_files(which="b"))
        
        self.delete_selected_both_button = QPushButton("删除选中的所有文件")
        self.delete_selected_both_button.clicked.connect(lambda: self._delete_selected_files(which="both"))
        
        batch_ops_layout.addWidget(self.delete_selected_a_button)
        batch_ops_layout.addWidget(self.delete_selected_b_button)
        batch_ops_layout.addWidget(self.delete_selected_both_button)
        
        find_same_files_layout.addWidget(self.find_same_files_table)
        find_same_files_layout.addLayout(batch_ops_layout)
        
        find_same_bottom_splitter.addWidget(self.find_same_files_group)
        
        # 日志显示区域 - 移到相同文件列表下方
        find_same_log_group = QGroupBox("比对日志")
        find_same_log_layout = QVBoxLayout()
        find_same_log_group.setLayout(find_same_log_layout)
        
        self.find_same_log_text = QTextEdit()
        self.find_same_log_text.setReadOnly(True)
        self.find_same_log_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.find_same_log_text.setUndoRedoEnabled(False)
        
        # 设置日志区域的背景和文本颜色
        find_same_log_palette = QPalette()
        find_same_log_palette.setColor(QPalette.ColorRole.Base, QColor(245, 245, 245))
        find_same_log_palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
        self.find_same_log_text.setPalette(find_same_log_palette)
        
        # 优化日志显示：设置固定字体，启用自动滚动
        self.find_same_log_text.setFont(QFont("Consolas", 9))
        self.find_same_log_text.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.find_same_log_text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        find_same_log_layout.addWidget(self.find_same_log_text)
        find_same_bottom_splitter.addWidget(find_same_log_group)
        
        find_same_bottom_splitter.setSizes([30, 170, 50])  # 进一步调整布局：大幅减少日志显示区域大小，为文件组区域提供更多空间
        
        self.find_same_tab_layout.addWidget(find_same_bottom_splitter)
        
        # ===== 重复文件查找页面 =====
        self.find_duplicate_tab_layout = QVBoxLayout(self.find_duplicate_tab)
        
        # 文件夹选择区域
        duplicate_folder_select_layout = QHBoxLayout()
        self.duplicate_folder_label = QLabel("目标文件夹:")
        self.duplicate_folder_edit = QLineEdit()
        self.duplicate_folder_edit.setReadOnly(True)
        self.duplicate_folder_button = QPushButton("浏览...")
        self.duplicate_folder_button.clicked.connect(self._browse_duplicate_folder)
        
        duplicate_folder_select_layout.addWidget(self.duplicate_folder_label)
        duplicate_folder_select_layout.addWidget(self.duplicate_folder_edit, 1)
        duplicate_folder_select_layout.addWidget(self.duplicate_folder_button)
        
        # 扫描按钮区域
        duplicate_scan_layout = QHBoxLayout()
        self.find_duplicate_button = QPushButton("开始扫描重复文件")
        self.find_duplicate_button.clicked.connect(self._find_duplicate_files)
        self.find_duplicate_button.setEnabled(False)  # 初始禁用
        duplicate_scan_layout.addWidget(self.find_duplicate_button)
        
        # 进度条和结果显示区域（上下结构）
        duplicate_bottom_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # 进度条和当前文件显示
        duplicate_progress_widget = QWidget()
        duplicate_progress_layout = QVBoxLayout(duplicate_progress_widget)
        self.duplicate_progress_bar = QProgressBar()
        self.duplicate_progress_bar.setRange(0, 100)
        self.duplicate_progress_bar.setValue(0)
        self.duplicate_progress_bar.setTextVisible(True)
        duplicate_progress_layout.addWidget(self.duplicate_progress_bar)
        
        # 添加当前文件显示标签
        self.duplicate_current_file_label = QLabel("当前文件: ")
        duplicate_progress_layout.addWidget(self.duplicate_current_file_label)
        duplicate_bottom_splitter.addWidget(duplicate_progress_widget)
        
        # 重复文件显示区域
        self.duplicate_files_group = QGroupBox("重复文件列表")
        duplicate_files_layout = QVBoxLayout(self.duplicate_files_group)
        
        # 创建重复文件表格
        self.duplicate_files_table = QTableWidget()
        self.duplicate_files_table.setColumnCount(4)
        # 更新表头，添加说明
        self.duplicate_files_table.setHorizontalHeaderLabels(["保留", "文件路径", "文件大小", "修改时间"])
        # 为除"保留"列外的所有列设置拉伸模式
        for i in range(1, 4):
            self.duplicate_files_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        # 为"保留"列设置固定宽度调整模式
        self.duplicate_files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        # 设置右键菜单
        self.duplicate_files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.duplicate_files_table.customContextMenuRequested.connect(self._show_duplicate_context_menu)
        
        # 批量操作区域
        duplicate_batch_ops_layout = QHBoxLayout()
        self.delete_selected_duplicate_button = QPushButton("删除选中的重复文件")
        self.delete_selected_duplicate_button.clicked.connect(self._delete_selected_duplicate_files)
        self.delete_selected_duplicate_button.setEnabled(False)
        
        # 添加全不选中按钮
        self.deselect_all_button = QPushButton("全不选中")
        self.deselect_all_button.clicked.connect(self._deselect_all_duplicate_files)
        self.deselect_all_button.setEnabled(False)
        
        # 添加操作说明标签
        self.duplicate_help_label = QLabel("说明：保留列 - 未勾选的文件将保留，勾选的文件将被删除")
        self.duplicate_help_label.setStyleSheet("color: #666; font-style: italic;")
        
        duplicate_batch_ops_layout.addWidget(self.delete_selected_duplicate_button)
        duplicate_batch_ops_layout.addWidget(self.deselect_all_button)
        duplicate_batch_ops_layout.addWidget(self.duplicate_help_label, 1, Qt.AlignmentFlag.AlignRight)
        
        duplicate_files_layout.addWidget(self.duplicate_files_table)
        duplicate_files_layout.addLayout(duplicate_batch_ops_layout)
        
        duplicate_bottom_splitter.addWidget(self.duplicate_files_group)
        duplicate_bottom_splitter.setSizes([30, 300])  # 初始大小
        
        # 添加所有组件到重复文件查找标签布局
        self.find_duplicate_tab_layout.addLayout(duplicate_folder_select_layout)
        self.find_duplicate_tab_layout.addLayout(duplicate_scan_layout)
        self.find_duplicate_tab_layout.addWidget(duplicate_bottom_splitter, 1)
        
        # ===== 文件夹搜身页面 =====
        self.file_slimming_tab_layout = QVBoxLayout(self.file_slimming_tab)
        
        # 文件夹选择区域
        file_slimming_folder_select_layout = QHBoxLayout()
        self.file_slimming_folder_label = QLabel("目标文件夹:")
        self.file_slimming_folder_edit = QLineEdit()
        self.file_slimming_folder_edit.setReadOnly(True)
        self.file_slimming_folder_button = QPushButton("浏览...")
        self.file_slimming_folder_button.clicked.connect(self._browse_file_slimming_folder)
        
        file_slimming_folder_select_layout.addWidget(self.file_slimming_folder_label)
        file_slimming_folder_select_layout.addWidget(self.file_slimming_folder_edit, 1)
        file_slimming_folder_select_layout.addWidget(self.file_slimming_folder_button)
        
        # 扫描按钮区域
        file_slimming_scan_layout = QHBoxLayout()
        self.start_file_slimming_button = QPushButton("开始扫描大文件")
        self.start_file_slimming_button.clicked.connect(self._start_file_slimming)
        self.start_file_slimming_button.setEnabled(False)  # 初始禁用
        
        self.pause_file_slimming_button = QPushButton("暂停")
        self.pause_file_slimming_button.clicked.connect(self._toggle_pause_file_slimming)
        self.pause_file_slimming_button.setEnabled(False)
        
        self.stop_file_slimming_button = QPushButton("停止")
        self.stop_file_slimming_button.clicked.connect(self._stop_file_slimming)
        self.stop_file_slimming_button.setEnabled(False)
        
        file_slimming_scan_layout.addWidget(self.start_file_slimming_button)
        file_slimming_scan_layout.addWidget(self.pause_file_slimming_button)
        file_slimming_scan_layout.addWidget(self.stop_file_slimming_button)
        
        # 进度条和结果显示区域（上下结构）
        file_slimming_bottom_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # 进度条和当前文件显示
        file_slimming_progress_widget = QWidget()
        file_slimming_progress_layout = QVBoxLayout(file_slimming_progress_widget)
        self.file_slimming_progress_bar = QProgressBar()
        self.file_slimming_progress_bar.setRange(0, 100)
        self.file_slimming_progress_bar.setValue(0)
        self.file_slimming_progress_bar.setTextVisible(True)
        file_slimming_progress_layout.addWidget(self.file_slimming_progress_bar)
        
        # 添加当前文件显示标签
        self.file_slimming_current_file_label = QLabel("当前文件: ")
        file_slimming_progress_layout.addWidget(self.file_slimming_current_file_label)
        file_slimming_bottom_splitter.addWidget(file_slimming_progress_widget)
        
        # 文件列表显示区域
        self.file_slimming_files_group = QGroupBox("文件列表（按大小排序）")
        file_slimming_files_layout = QVBoxLayout(self.file_slimming_files_group)
        
        # 创建文件表格
        self.file_slimming_files_table = QTableWidget()
        self.file_slimming_files_table.setColumnCount(4)
        self.file_slimming_files_table.setHorizontalHeaderLabels(["文件名", "文件路径", "文件大小", "修改时间"])
        self.file_slimming_files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # 启用表头排序功能
        self.file_slimming_files_table.setSortingEnabled(False)  # 初始禁用排序，填充数据后再启用
        
        # 设置右键菜单
        self.file_slimming_files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_slimming_files_table.customContextMenuRequested.connect(self._show_file_slimming_context_menu)
        
        # 批量操作区域
        file_slimming_batch_ops_layout = QHBoxLayout()
        self.copy_selected_files_button = QPushButton("复制所选文件")
        self.copy_selected_files_button.clicked.connect(lambda: self._process_selected_files("copy"))
        self.copy_selected_files_button.setEnabled(False)
        
        self.move_selected_files_button = QPushButton("移动所选文件")
        self.move_selected_files_button.clicked.connect(lambda: self._process_selected_files("move"))
        self.move_selected_files_button.setEnabled(False)
        
        self.delete_selected_files_button = QPushButton("删除所选文件")
        self.delete_selected_files_button.clicked.connect(self._delete_selected_files_from_slimming)
        self.delete_selected_files_button.setEnabled(False)
        
        file_slimming_batch_ops_layout.addWidget(self.copy_selected_files_button)
        file_slimming_batch_ops_layout.addWidget(self.move_selected_files_button)
        file_slimming_batch_ops_layout.addWidget(self.delete_selected_files_button)
        
        file_slimming_files_layout.addWidget(self.file_slimming_files_table)
        file_slimming_files_layout.addLayout(file_slimming_batch_ops_layout)
        
        file_slimming_bottom_splitter.addWidget(self.file_slimming_files_group)
        file_slimming_bottom_splitter.setSizes([30, 300])  # 初始大小
        
        # 添加所有组件到文件夹搜身标签布局
        self.file_slimming_tab_layout.addLayout(file_slimming_folder_select_layout)
        self.file_slimming_tab_layout.addLayout(file_slimming_scan_layout)
        self.file_slimming_tab_layout.addWidget(file_slimming_bottom_splitter, 1)
        
        # 初始化文件夹搜身相关变量
        self.file_slimming_thread = None
        self.file_slimming_files = []
        self.is_file_slimming_paused = False
        
        # ===== 文件夹大小页面 =====
        self.folder_size_tab_layout = QVBoxLayout(self.folder_size_tab)
        
        # 文件夹选择区域
        folder_size_folder_select_layout = QHBoxLayout()
        self.folder_size_folder_label = QLabel("目标文件夹:")
        self.folder_size_folder_edit = QLineEdit()
        self.folder_size_folder_edit.setReadOnly(True)
        self.folder_size_folder_button = QPushButton("浏览...")
        self.folder_size_folder_button.clicked.connect(self._browse_folder_size_folder)
        
        folder_size_folder_select_layout.addWidget(self.folder_size_folder_label)
        folder_size_folder_select_layout.addWidget(self.folder_size_folder_edit, 1)
        folder_size_folder_select_layout.addWidget(self.folder_size_folder_button)
        
        # 扫描按钮区域
        folder_size_scan_layout = QHBoxLayout()
        self.start_folder_size_button = QPushButton("开始计算文件夹大小")
        self.start_folder_size_button.clicked.connect(self._start_folder_size)
        self.start_folder_size_button.setEnabled(False)  # 初始禁用
        
        self.pause_folder_size_button = QPushButton("暂停")
        self.pause_folder_size_button.clicked.connect(self._toggle_pause_folder_size)
        self.pause_folder_size_button.setEnabled(False)
        
        self.stop_folder_size_button = QPushButton("停止")
        self.stop_folder_size_button.clicked.connect(self._stop_folder_size)
        self.stop_folder_size_button.setEnabled(False)
        
        folder_size_scan_layout.addWidget(self.start_folder_size_button)
        folder_size_scan_layout.addWidget(self.pause_folder_size_button)
        folder_size_scan_layout.addWidget(self.stop_folder_size_button)
        
        # 进度条和结果显示区域（上下结构）
        folder_size_bottom_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # 进度条和当前文件夹显示
        folder_size_progress_widget = QWidget()
        folder_size_progress_layout = QVBoxLayout(folder_size_progress_widget)
        self.folder_size_progress_bar = QProgressBar()
        self.folder_size_progress_bar.setRange(0, 100)
        self.folder_size_progress_bar.setValue(0)
        self.folder_size_progress_bar.setTextVisible(True)
        folder_size_progress_layout.addWidget(self.folder_size_progress_bar)
        
        # 添加当前文件夹显示标签
        self.folder_size_current_folder_label = QLabel("当前文件夹: ")
        folder_size_progress_layout.addWidget(self.folder_size_current_folder_label)
        folder_size_bottom_splitter.addWidget(folder_size_progress_widget)
        
        # 文件夹列表显示区域
        self.folder_size_folders_group = QGroupBox("文件夹列表（按大小排序）")
        folder_size_folders_layout = QVBoxLayout(self.folder_size_folders_group)
        
        # 创建文件夹表格
        self.folder_size_folders_table = QTableWidget()
        self.folder_size_folders_table.setColumnCount(5)
        self.folder_size_folders_table.setHorizontalHeaderLabels(["文件夹名称", "文件夹路径", "文件夹大小", "文件数量", "修改时间"])
        self.folder_size_folders_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # 启用表头排序功能
        self.folder_size_folders_table.setSortingEnabled(False)  # 初始禁用排序，填充数据后再启用
        
        # 设置右键菜单
        self.folder_size_folders_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.folder_size_folders_table.customContextMenuRequested.connect(self._show_folder_size_context_menu)
        
        # 批量操作区域
        folder_size_batch_ops_layout = QHBoxLayout()
        self.copy_selected_folders_button = QPushButton("复制所选文件夹")
        self.copy_selected_folders_button.clicked.connect(lambda: self._process_selected_folders("copy"))
        self.copy_selected_folders_button.setEnabled(False)
        
        self.move_selected_folders_button = QPushButton("移动所选文件夹")
        self.move_selected_folders_button.clicked.connect(lambda: self._process_selected_folders("move"))
        self.move_selected_folders_button.setEnabled(False)
        
        self.delete_selected_folders_button = QPushButton("删除所选文件夹")
        self.delete_selected_folders_button.clicked.connect(self._delete_selected_folders)
        self.delete_selected_folders_button.setEnabled(False)
        
        folder_size_batch_ops_layout.addWidget(self.copy_selected_folders_button)
        folder_size_batch_ops_layout.addWidget(self.move_selected_folders_button)
        folder_size_batch_ops_layout.addWidget(self.delete_selected_folders_button)
        
        folder_size_folders_layout.addWidget(self.folder_size_folders_table)
        folder_size_folders_layout.addLayout(folder_size_batch_ops_layout)
        
        folder_size_bottom_splitter.addWidget(self.folder_size_folders_group)
        folder_size_bottom_splitter.setSizes([30, 300])  # 初始大小
        
        # 添加所有组件到文件夹大小标签布局
        self.folder_size_tab_layout.addLayout(folder_size_folder_select_layout)
        self.folder_size_tab_layout.addLayout(folder_size_scan_layout)
        self.folder_size_tab_layout.addWidget(folder_size_bottom_splitter, 1)
        
        # 初始化文件夹大小相关变量
        self.folder_size_thread = None
        self.folder_size_folders = []
        self.is_folder_size_paused = False
        
        # 添加TabWidget到主布局
        main_layout.addWidget(self.tab_widget, 1)
        
        # ===== 状态栏 =====
        self.status_bar = self.window.statusBar()
        self.status_bar.showMessage("就绪")
        
        # 注意：窗口将在run方法中显示
    
    def _init_tkinter_ui(self):
        """使用Tkinter初始化界面"""
        self.root = tk.Tk()
        self.root.title("文件夹管理工具 - Myfile")
        self.root.geometry("1200x700")
        
        # 设置中文字体
        try:
            self.root.option_add("*Font", "微软雅黑 9")
        except:
            pass
        
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ===== 任务类型选择 =====
        task_frame = ttk.LabelFrame(main_frame, text="任务类型", padding="5")
        task_frame.pack(fill=tk.X, pady=5)
        
        self.task_type_var = tk.StringVar(value="sync")
        sync_radio = ttk.Radiobutton(task_frame, text="文件同步", variable=self.task_type_var, value="sync", command=self._on_task_type_changed)
        same_files_radio = ttk.Radiobutton(task_frame, text="相同文件比对", variable=self.task_type_var, value="find_same", command=self._on_task_type_changed)
        duplicate_radio = ttk.Radiobutton(task_frame, text="重复文件查找", variable=self.task_type_var, value="find_duplicate", command=self._on_task_type_changed)
        
        sync_radio.pack(side=tk.LEFT, padx=10)
        same_files_radio.pack(side=tk.LEFT, padx=10)
        duplicate_radio.pack(side=tk.LEFT, padx=10)
        
        # ===== 重复文件查找页面 - Tkinter版 =====
        self.duplicate_frame = ttk.LabelFrame(main_frame, text="重复文件查找", padding="5")
        self.duplicate_frame.pack_forget()  # 初始隐藏
        
        # 文件夹选择
        duplicate_folder_frame = ttk.Frame(self.duplicate_frame)
        duplicate_folder_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(duplicate_folder_frame, text="选择扫描文件夹:").pack(side=tk.LEFT, padx=5)
        self.duplicate_folder_var = tk.StringVar()
        self.duplicate_folder_entry = ttk.Entry(duplicate_folder_frame, textvariable=self.duplicate_folder_var, width=50)
        self.duplicate_folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.duplicate_folder_button = ttk.Button(duplicate_folder_frame, text="浏览...", command=self._browse_duplicate_folder)
        self.duplicate_folder_button.pack(side=tk.LEFT, padx=5)
        
        # 扫描按钮
        duplicate_scan_frame = ttk.Frame(self.duplicate_frame)
        duplicate_scan_frame.pack(fill=tk.X, pady=5)
        
        self.find_duplicate_button = ttk.Button(duplicate_scan_frame, text="开始扫描重复文件", command=self._find_duplicate_files)
        self.find_duplicate_button.pack(side=tk.LEFT, padx=5)
        
        # 进度条
        self.duplicate_progress_var = tk.DoubleVar()
        self.duplicate_progress_bar = ttk.Progressbar(self.duplicate_frame, variable=self.duplicate_progress_var, maximum=100)
        self.duplicate_progress_bar.pack(fill=tk.X, pady=5)
        
        # 当前文件显示标签
        self.duplicate_current_file_label = ttk.Label(self.duplicate_frame, text="当前文件: ")
        self.duplicate_current_file_label.pack(anchor=tk.W, pady=5)
        
        # 当前扫描文件
        self.duplicate_current_file_var = tk.StringVar(value="准备就绪")
        ttk.Label(self.duplicate_frame, textvariable=self.duplicate_current_file_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # 重复文件显示区域
        duplicate_files_frame = ttk.LabelFrame(self.duplicate_frame, text="重复文件列表", padding="5")
        duplicate_files_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("checkbox", "path", "size", "modified")
        self.duplicate_files_tree = ttk.Treeview(duplicate_files_frame, columns=columns, show="headings")
        self.duplicate_files_tree.heading("checkbox", text="保留")
        self.duplicate_files_tree.heading("path", text="文件路径")
        self.duplicate_files_tree.heading("size", text="文件大小")
        self.duplicate_files_tree.heading("modified", text="修改时间")
        
        self.duplicate_files_tree.column("checkbox", width=50, anchor=tk.CENTER)
        self.duplicate_files_tree.column("path", width=400, anchor=tk.W)
        self.duplicate_files_tree.column("size", width=100, anchor=tk.E)
        self.duplicate_files_tree.column("modified", width=150, anchor=tk.CENTER)
        
        # 添加滚动条
        duplicate_scrollbar = ttk.Scrollbar(duplicate_files_frame, orient=tk.VERTICAL, command=self.duplicate_files_tree.yview)
        self.duplicate_files_tree.configure(yscroll=duplicate_scrollbar.set)
        
        duplicate_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.duplicate_files_tree.pack(fill=tk.BOTH, expand=True)
        
        # 删除按钮
        duplicate_delete_frame = ttk.Frame(self.duplicate_frame)
        duplicate_delete_frame.pack(fill=tk.X, pady=5)
        
        self.delete_selected_duplicate_button = ttk.Button(duplicate_delete_frame, text="删除选中的重复文件", command=self._delete_selected_duplicate_files)
        self.delete_selected_duplicate_button.pack(side=tk.LEFT, padx=5)
        
        # ===== 文件夹选择和内容显示区域（左右结构）=====
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 左侧：源文件夹
        left_frame = ttk.LabelFrame(folder_frame, text="源文件夹 A", padding="5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # 源文件夹选择
        left_folder_frame = ttk.Frame(left_frame)
        left_folder_frame.pack(fill=tk.X, pady=5)
        
        self.folder_a_var = tk.StringVar()
        self.folder_a_edit = ttk.Entry(left_folder_frame, textvariable=self.folder_a_var)
        self.folder_a_edit.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.browse_a_btn = ttk.Button(left_folder_frame, text="浏览...", command=self._browse_folder_a)
        self.browse_a_btn.pack(side=tk.RIGHT, padx=5)
        
        # 源文件夹内容显示
        self.source_tree_frame = ttk.Frame(left_frame)
        self.source_tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建Treeview用于显示文件列表
        columns = ("name", "size", "type", "modified")
        self.source_tree = ttk.Treeview(self.source_tree_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.source_tree.heading("name", text="名称")
        self.source_tree.heading("size", text="大小")
        self.source_tree.heading("type", text="类型")
        self.source_tree.heading("modified", text="修改时间")
        
        # 设置列宽
        self.source_tree.column("name", width=200)
        self.source_tree.column("size", width=80, anchor=tk.E)
        self.source_tree.column("type", width=80)
        self.source_tree.column("modified", width=150)
        
        # 添加滚动条
        source_scrollbar = ttk.Scrollbar(self.source_tree_frame, orient=tk.VERTICAL, command=self.source_tree.yview)
        self.source_tree.configure(yscroll=source_scrollbar.set)
        
        # 添加右键菜单（Tkinter模式）
        self.source_tree.bind("<Button-3>", lambda event: self._show_tk_source_context_menu(event, self.source_tree))
        
        # 布局
        source_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.source_tree.pack(fill=tk.BOTH, expand=True)
        
        # 右侧：目标文件夹
        right_frame = ttk.LabelFrame(folder_frame, text="目标文件夹 B", padding="5")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # 目标文件夹选择
        right_folder_frame = ttk.Frame(right_frame)
        right_folder_frame.pack(fill=tk.X, pady=5)
        
        self.folder_b_var = tk.StringVar()
        self.folder_b_edit = ttk.Entry(right_folder_frame, textvariable=self.folder_b_var)
        self.folder_b_edit.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.browse_b_btn = ttk.Button(right_folder_frame, text="浏览...", command=self._browse_folder_b)
        self.browse_b_btn.pack(side=tk.RIGHT, padx=5)
        
        # 目标文件夹内容显示
        self.target_tree_frame = ttk.Frame(right_frame)
        self.target_tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建Treeview用于显示文件列表
        self.target_tree = ttk.Treeview(self.target_tree_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.target_tree.heading("name", text="名称")
        self.target_tree.heading("size", text="大小")
        self.target_tree.heading("type", text="类型")
        self.target_tree.heading("modified", text="修改时间")
        
        # 设置列宽
        self.target_tree.column("name", width=200)
        self.target_tree.column("size", width=80, anchor=tk.E)
        self.target_tree.column("type", width=80)
        self.target_tree.column("modified", width=150)
        
        # 添加滚动条
        target_scrollbar = ttk.Scrollbar(self.target_tree_frame, orient=tk.VERTICAL, command=self.target_tree.yview)
        self.target_tree.configure(yscroll=target_scrollbar.set)
        
        # 添加右键菜单（Tkinter模式）
        self.target_tree.bind("<Button-3>", lambda event: self._show_tk_target_context_menu(event, self.target_tree))
        
        # 布局
        target_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.target_tree.pack(fill=tk.BOTH, expand=True)
        
        # ===== 同步选项区域 =====
        options_frame = ttk.LabelFrame(main_frame, text="同步选项", padding="5")
        options_frame.pack(fill=tk.X, pady=5)
        
        # 同步模式
        ttk.Label(options_frame, text="同步模式:").grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.sync_mode_var = tk.StringVar(value="A → B (单向)")
        self.sync_mode_combo = ttk.Combobox(options_frame, textvariable=self.sync_mode_var)
        self.sync_mode_combo['values'] = ["A → B (单向)", "B → A (单向)", "A ↔ B (双向)"]
        self.sync_mode_combo.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # 忽略规则
        ttk.Label(options_frame, text="忽略规则:").grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.ignore_var = tk.StringVar()
        self.ignore_edit = ttk.Entry(options_frame, textvariable=self.ignore_var, width=50)
        self.ignore_edit.insert(0, "例如: *.tmp, *.bak")
        self.ignore_edit.grid(row=1, column=1, sticky=tk.EW, pady=2)
        
        # 同步删除选项
        self.sync_delete_var = tk.BooleanVar()
        self.sync_delete_check = ttk.Checkbutton(options_frame, text="同步删除（删除目标中多余的文件）", 
                                               variable=self.sync_delete_var)
        self.sync_delete_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        options_frame.columnconfigure(1, weight=1)
        
        # ===== 按钮区域 =====
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        self.start_btn = ttk.Button(buttons_frame, text="开始同步", command=self._start_sync)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.find_same_files_btn = ttk.Button(buttons_frame, text="查找相同文件", command=self._find_same_files, state=tk.DISABLED)
        self.find_same_files_btn.pack(side=tk.LEFT, padx=5)
        
        self.pause_btn = ttk.Button(buttons_frame, text="暂停", command=self._pause_sync, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(buttons_frame, text="停止", command=self._stop_sync, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # ===== 进度条 =====
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # ===== 日志显示区域 =====
        self.log_frame = ttk.LabelFrame(main_frame, text="同步日志", padding="5")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # ===== 相同文件显示区域 =====
        self.same_files_frame = ttk.LabelFrame(main_frame, text="相同文件列表", padding="5")
        # 创建相同文件表格
        columns = ("file_a", "file_b", "actions")
        self.same_files_tree = ttk.Treeview(self.same_files_frame, columns=columns, show="headings")
        self.same_files_tree.heading("file_a", text="源文件夹文件")
        self.same_files_tree.heading("file_b", text="目标文件夹文件")
        self.same_files_tree.heading("actions", text="操作")
        
        self.same_files_tree.column("file_a", width=300, anchor=tk.W)
        self.same_files_tree.column("file_b", width=300, anchor=tk.W)
        self.same_files_tree.column("actions", width=150, anchor=tk.CENTER)
        
        # 添加滚动条
        tree_scroll = ttk.Scrollbar(self.same_files_frame, orient=tk.VERTICAL, command=self.same_files_tree.yview)
        self.same_files_tree.configure(yscroll=tree_scroll.set)
        
        # 删除选中按钮
        delete_selected_button = ttk.Button(self.same_files_frame, text="删除选中文件", command=self._delete_selected_files)
        
        # 布局
        self.same_files_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.LEFT, fill=tk.Y)
        delete_selected_button.pack(pady=5)
        
        # 默认隐藏相同文件区域
        self.same_files_frame.pack_forget()
        
        # ===== 状态栏 =====
        self.status_var = tk.StringVar(value="就绪")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _browse_folder_a(self):
        """浏览选择文件夹A"""
        folder = self._get_directory()
        if folder:
            if PYQT_AVAILABLE:
                # 根据当前选中的Tab确定使用哪个界面的组件
                current_tab = self.tab_widget.currentIndex()
                if current_tab == 0:  # 同步页面
                    self.sync_folder_a_edit.setText(folder)
                    # 更新同步页面源文件夹内容显示
                    if QFileSystemModel is not None:
                        self._set_root_index_safe(self.sync_source_tree, self.sync_source_model, folder)
                        # 只要两个文件夹都已选择，就立即开始比对（默认显示不同文件）
                        if self.sync_folder_b_edit.text():
                            self._auto_compare_if_ready(force=True)
                        # 同步高度
                        self._sync_tree_heights()
                else:  # 相同文件比对页面
                    self.find_same_folder_a_edit.setText(folder)
                    # 更新比对页面源文件夹内容显示
                    if QFileSystemModel is not None:
                        self._set_root_index_safe(self.find_same_source_tree, self.find_same_source_model, folder)
                    # 只要两个文件夹都已选择，就立即开始比对（自动比对）
                    if self.find_same_folder_b_edit.text():
                        self._find_same_files()
            else:
                self.folder_a_var.set(folder)
                # 更新源文件夹内容显示
                self._update_tree_content(self.source_tree, folder)
    
    def _browse_folder_b(self):
        """浏览选择文件夹B"""
        folder = self._get_directory()
        if folder:
            if PYQT_AVAILABLE:
                # 根据当前选中的Tab确定使用哪个界面的组件
                current_tab = self.tab_widget.currentIndex()
                if current_tab == 0:  # 同步页面
                    self.sync_folder_b_edit.setText(folder)
                    # 更新同步页面目标文件夹内容显示
                    if QFileSystemModel is not None:
                        self._set_root_index_safe(self.sync_target_tree, self.sync_target_model, folder)
                        # 只要两个文件夹都已选择，就立即开始比对（默认显示不同文件）
                    if self.sync_folder_a_edit.text():
                        self._auto_compare_if_ready(force=True)
                        # 同步高度
                        self._sync_tree_heights()
                else:  # 相同文件比对页面
                    self.find_same_folder_b_edit.setText(folder)
                    # 更新比对页面目标文件夹内容显示
                    if QFileSystemModel is not None:
                        self._set_root_index_safe(self.find_same_target_tree, self.find_same_target_model, folder)
                    # 只要两个文件夹都已选择，就立即开始比对（自动比对）
                    if self.find_same_folder_a_edit.text():
                        # 修改：只调用一次查找方法，避免重复启动线程
                        self._find_same_files_with_no_duplicates()
            else:
                self.folder_b_var.set(folder)
                # 更新目标文件夹内容显示
                self._update_tree_content(self.target_tree, folder)
    
    def _find_same_files_with_no_duplicates(self):
        """查找相同文件但不显示重复项"""
        # 获取文件夹路径
        if PYQT_AVAILABLE:
            dir_a = self.find_same_folder_a_edit.text().strip()
            dir_b = self.find_same_folder_b_edit.text().strip()
            ignore_patterns = self.find_same_ignore_edit.text().strip()
        else:
            dir_a = self.folder_a_var.get().strip()
            dir_b = self.folder_b_var.get().strip()
            ignore_patterns = self.ignore_var.get().strip()
        
        # 验证文件夹路径
        if not dir_a or not os.path.isdir(dir_a):
            self._show_error("错误", "请选择有效的源文件夹 A")
            return
        
        if not dir_b or not os.path.isdir(dir_b):
            self._show_error("错误", "请选择有效的目标文件夹 B")
            return
        
        # 清空相同文件列表
        self._clear_same_files()
        
        # 清空并初始化相同文件比对日志
        self._clear_find_same_log()
        self._log_message("准备查找相同文件...", source="find_same")
        
        # 设置运行状态
        self.running = True
        
        # 禁用相关按钮
        self._set_buttons_state(False)
        
        # 停止之前可能存在的线程
        if hasattr(self, 'sync_thread') and self.sync_thread:
            print("[DEBUG] 停止之前可能存在的线程")
            try:
                self.sync_thread.stop()
                print("[DEBUG] 已调用线程的stop方法")
                if PYQT_AVAILABLE and hasattr(self.sync_thread, 'wait'):
                    # 增加超时控制
                    print("[DEBUG] 等待线程结束，最多5秒")
                    if not self.sync_thread.wait(5000):  # 5秒超时
                        self._log_message("警告：线程未在预期时间内停止", source="find_same")
                        print("[DEBUG] 警告：线程未在预期时间内停止")
                    else:
                        print("[DEBUG] 线程已成功终止")
                else:
                    print("[DEBUG] 非PyQt模式或线程没有wait方法，等待线程自然结束")
            except Exception as e:
                error_msg = f"停止线程时出错: {str(e)}"
                self._log_message(error_msg, source="find_same")
                print(f"[DEBUG] {error_msg}")
            finally:
                # 即使出错，也要清除引用
                self.sync_thread = None
                print("[DEBUG] 已清除线程引用")
        
        # 确保同步引擎存在
        if not hasattr(self, 'sync_engine') or not self.sync_engine:
            print("[DEBUG] 同步引擎不存在，正在创建...")
            # 重新初始化同步引擎
            self.sync_engine = SyncEngine()
            print("[DEBUG] 同步引擎创建成功")
        else:
            print("[DEBUG] 同步引擎已存在")
        
        # 创建并启动任务线程，传递show_duplicates=False参数
        self.sync_thread = SyncThread(
            self.sync_engine, 
            dir_a, 
            dir_b, 
            task_type="find_same",
            ignore_patterns=ignore_patterns
        )
        
        if PYQT_AVAILABLE:
            # 连接信号 - 使用特定的日志处理方法
            self.sync_thread.progress_updated.connect(lambda value: self.find_same_progress_bar.setValue(value))
            self.sync_thread.log_updated.connect(lambda msg: self._log_message(msg, source="find_same"))
            self.sync_thread.sync_completed.connect(self._sync_completed)
            self.sync_thread.same_files_found.connect(self._display_same_files_no_duplicates)
            self.sync_thread.current_file_updated.connect(self._update_current_file)  # 连接当前文件更新信号
            
            # 启动线程
            self.sync_thread.start()
        else:
            # 设置回调 - Tkinter模式暂时保持使用默认日志
            self.sync_thread.progress_callback = self._update_progress
            self.sync_thread.log_callback = lambda msg: self._log_message(msg, source="find_same")
            self.sync_thread.completed_callback = self._sync_completed
            self.sync_thread.same_files_callback = self._display_same_files_no_duplicates
            self.sync_thread.current_file_callback = self._update_current_file  # 设置当前文件回调
            
            # 启动线程
            self.sync_thread.start()
            
            # 启动定时器更新进度和日志
            self._update_sync_ui()
    
    def _display_same_files_no_duplicates(self, same_files):
        """显示找到的相同文件，但不显示重复项"""
        if PYQT_AVAILABLE:
            # 清空表格
            self.find_same_files_table.setRowCount(0)
            
            # 过滤重复文件
            filtered_files = []
            seen_pairs = set()
            for file_a, file_b in same_files:
                # 将文件对排序，确保不同顺序的相同对被视为同一个
                sorted_pair = tuple(sorted([file_a, file_b]))
                if sorted_pair not in seen_pairs:
                    seen_pairs.add(sorted_pair)
                    filtered_files.append((file_a, file_b))
            
            # 添加数据
            for i, (file_a, file_b) in enumerate(filtered_files):
                self.find_same_files_table.insertRow(i)
                
                # 添加文件路径
                self.find_same_files_table.setItem(i, 0, QTableWidgetItem(file_a))
                self.find_same_files_table.setItem(i, 1, QTableWidgetItem(file_b))
                
                # 添加删除按钮组
                button_widget = QWidget()
                layout = QHBoxLayout(button_widget)
                layout.setContentsMargins(2, 2, 2, 2)
                
                # 删除源文件按钮
                delete_a_btn = QPushButton("删除A")
                delete_a_btn.setToolTip(f"删除源文件: {file_a}")
                delete_a_btn.setProperty("file_a", file_a)
                delete_a_btn.setProperty("file_b", file_b)
                delete_a_btn.setProperty("delete_type", "a")
                delete_a_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="a": self._delete_file(a, b, t))
                layout.addWidget(delete_a_btn)
                
                # 删除目标文件按钮
                delete_b_btn = QPushButton("删除B")
                delete_b_btn.setToolTip(f"删除目标文件: {file_b}")
                delete_b_btn.setProperty("file_a", file_a)
                delete_b_btn.setProperty("file_b", file_b)
                delete_b_btn.setProperty("delete_type", "b")
                delete_b_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="b": self._delete_file(a, b, t))
                layout.addWidget(delete_b_btn)
                
                # 删除全部按钮
                delete_all_btn = QPushButton("删除全部")
                delete_all_btn.setToolTip(f"同时删除两个文件")
                delete_all_btn.setProperty("file_a", file_a)
                delete_all_btn.setProperty("file_b", file_b)
                delete_all_btn.setProperty("delete_type", "all")
                delete_all_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="all": self._delete_file(a, b, t))
                layout.addWidget(delete_all_btn)
                
                self.find_same_files_table.setCellWidget(i, 2, button_widget)
        else:
            # 清空树形视图
            for item in self.same_files_tree.get_children():
                self.same_files_tree.delete(item)
            
            # 过滤重复文件
            filtered_files = []
            seen_pairs = set()
            for file_a, file_b in same_files:
                # 将文件对排序，确保不同顺序的相同对被视为同一个
                sorted_pair = tuple(sorted([file_a, file_b]))
                if sorted_pair not in seen_pairs:
                    seen_pairs.add(sorted_pair)
                    filtered_files.append((file_a, file_b))
            
            # 添加数据
            for i, (file_a, file_b) in enumerate(filtered_files):
                item_id = self.same_files_tree.insert('', tk.END, values=(file_a, file_b, "删除"))
                
                # 为每个项目添加绑定删除功能的按钮（简化处理，通过选中后点击删除按钮）
        
        self._log_message(f"找到 {len(filtered_files)} 对相同文件（已过滤重复项）", source="find_same")
        self._set_status(f"找到 {len(filtered_files)} 对相同文件（已过滤重复项）")
    
    def _get_directory(self):
        """获取选择的目录"""
        if PYQT_AVAILABLE:
            return QFileDialog.getExistingDirectory(self.window, "选择目录")
        else:
            return filedialog.askdirectory()
    
    def _browse_duplicate_folder(self):
        """浏览选择重复文件扫描的目标文件夹"""
        directory = self._get_directory()
        if directory:
            self.duplicate_folder_edit.setText(directory)
            self.find_duplicate_button.setEnabled(True)
            self._log_message(f"已选择重复文件扫描目录: {directory}")
    
    def _tab_changed(self, index):
        """Tab切换时的处理"""
        # 根据任务运行状态设置按钮状态，而不是总是启用
        self._set_buttons_state(not self.running)
        
        # 根据当前Tab更新状态栏
        if index == 0:
            self._set_status("文件同步模式就绪")
        elif index == 1:
            self._set_status("相同文件比对模式就绪")
        else:  # 重复文件查找页面
            self._set_status("重复文件查找模式就绪")
            # 重复文件查找标签页特有初始化
            if hasattr(self, 'delete_selected_duplicate_button'):
                # 更新删除按钮状态
                self.delete_selected_duplicate_button.setEnabled(False)
            
    def _on_task_type_changed(self):
        """在Tkinter模式下任务类型变更时的处理"""
        task_type = self.task_type_var.get()
        
        # 隐藏所有任务相关的控件
        for widget in [self.sync_options_frame, self.buttons_frame, self.log_frame, self.same_files_frame, self.duplicate_frame]:
            widget.pack_forget()
        
        # 根据任务类型显示对应的控件
        if task_type == "sync":
            self.sync_options_frame.pack(fill=tk.X, pady=5)
            self.buttons_frame.pack(fill=tk.X, pady=5)
            self.progress_bar.pack(fill=tk.X, pady=5)
            self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            self._set_status("文件同步模式就绪")
        elif task_type == "find_same":
            self.buttons_frame.pack_forget()  # 隐藏同步相关的按钮
            self.same_files_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            self.progress_bar.pack(fill=tk.X, pady=5)
            self.log_frame.pack_forget()  # 隐藏日志框
            self._set_status("相同文件比对模式就绪")
        elif task_type == "find_duplicate":
            self.buttons_frame.pack_forget()  # 隐藏同步相关的按钮
            self.duplicate_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            self.log_frame.pack_forget()  # 隐藏日志框
            self._set_status("重复文件查找模式就绪")
    
    def _start_sync(self):
        """开始同步"""
        # 获取文件夹路径
        if PYQT_AVAILABLE:
            dir_a = self.sync_folder_a_edit.text().strip()
            dir_b = self.sync_folder_b_edit.text().strip()
            sync_mode_text = self.sync_mode_combo.currentText()
            ignore_patterns = self.sync_ignore_edit.text().strip()
            sync_delete = self.sync_delete_check.isChecked()
        else:
            dir_a = self.folder_a_var.get().strip()
            dir_b = self.folder_b_var.get().strip()
            sync_mode_text = self.sync_mode_var.get()
            ignore_patterns = self.ignore_var.get().strip()
            sync_delete = self.sync_delete_var.get()
        
        # 验证文件夹路径
        if not dir_a or not os.path.isdir(dir_a):
            self._show_error("错误", "请选择有效的源文件夹 A")
            return
        
        if not dir_b or not os.path.isdir(dir_b):
            self._show_error("错误", "请选择有效的目标文件夹 B")
            return
        
        # 转换同步模式
        if sync_mode_text == "A → B (单向)":
            sync_mode = "a_to_b"
        elif sync_mode_text == "B → A (单向)":
            sync_mode = "b_to_a"
        else:  # A ↔ B (双向)
            sync_mode = "two_way"
        
        # 清空日志
        self._clear_log()
        self._log_message("准备同步...")
        
        # 禁用相关按钮
        self._set_buttons_state(False)
        
        # 创建并启动同步线程
        self.sync_thread = SyncThread(
            self.sync_engine, 
            dir_a, 
            dir_b, 
            task_type="sync",
            sync_mode=sync_mode, 
            sync_delete=sync_delete, 
            ignore_patterns=ignore_patterns
        )
        
        if PYQT_AVAILABLE:
            # 连接信号
            self.sync_thread.progress_updated.connect(lambda value: self.sync_progress_bar.setValue(value))
            self.sync_thread.log_updated.connect(self._log_message)
            self.sync_thread.sync_completed.connect(self._sync_completed)
            
            # 启动线程
            self.sync_thread.start()
        else:
            # 设置回调
            self.sync_thread.progress_callback = self._update_progress
            self.sync_thread.log_callback = self._log_message
            self.sync_thread.completed_callback = self._sync_completed
            
            # 启动线程
            self.sync_thread.start()
            
            # 启动定时器更新进度和日志
            self._update_sync_ui()
    
    def _find_same_files(self):
        """查找相同文件"""
        print("[DEBUG] _find_same_files方法开始执行")
        
        # 确保在方法开始时重置所有状态
        self.running = False
        
        try:
            # 获取文件夹路径
            if PYQT_AVAILABLE:
                dir_a = self.find_same_folder_a_edit.text().strip()
                dir_b = self.find_same_folder_b_edit.text().strip()
                ignore_patterns = self.find_same_ignore_edit.text().strip()
                print(f"[DEBUG] PyQt模式: 源文件夹路径A={dir_a}, 文件夹路径B={dir_b}")
            else:
                dir_a = self.folder_a_var.get().strip()
                dir_b = self.folder_b_var.get().strip()
                ignore_patterns = self.ignore_var.get().strip()
                print(f"[DEBUG] Tkinter模式: 源文件夹路径A={dir_a}, 文件夹路径B={dir_b}")
            
            # 验证文件夹路径
            if not dir_a or not os.path.isdir(dir_a):
                self._show_error("错误", "请选择有效的源文件夹 A")
                print("[DEBUG] 源文件夹A无效")
                return
            
            if not dir_b or not os.path.isdir(dir_b):
                self._show_error("错误", "请选择有效的目标文件夹 B")
                print("[DEBUG] 源文件夹B无效")
                return
            
            print("[DEBUG] 文件夹路径验证通过")
            
            # 清空相同文件列表
            self._clear_same_files()
            print("[DEBUG] 已清空相同文件列表")
            
            # 清空并初始化相同文件比对日志
            self._clear_find_same_log()
            self._log_message("准备查找相同文件...", source="find_same")
            print("[DEBUG] 已清空日志并初始化")
            
            # 设置运行状态
            self.running = True
            print("[DEBUG] 运行状态设置为True")
            
            # 禁用相关按钮
            self._set_buttons_state(False)
            print("[DEBUG] 相关按钮已禁用")
            
            # 停止之前可能存在的线程
            if hasattr(self, 'sync_thread') and self.sync_thread:
                print("[DEBUG] 停止之前可能存在的线程")
                try:
                    self.sync_thread.stop()
                    print("[DEBUG] 已调用线程的stop方法")
                    
                    # 等待线程完全停止
                    if PYQT_AVAILABLE and hasattr(self.sync_thread, 'wait'):
                        # 增加超时控制
                        print("[DEBUG] 等待线程结束，最多5秒")
                        if not self.sync_thread.wait(5000):  # 5秒超时
                            self._log_message("警告：线程未在预期时间内停止", source="find_same")
                            print("[DEBUG] 警告：线程未在预期时间内停止")
                        else:
                            print("[DEBUG] 线程已成功终止")
                    else:
                        print("[DEBUG] 非PyQt模式或线程没有wait方法，等待线程自然结束")
                        import time
                        time.sleep(2)  # 等待2秒确保线程停止
                        
                except Exception as e:
                    error_msg = f"停止线程时出错: {str(e)}"
                    self._log_message(error_msg, source="find_same")
                    print(f"[DEBUG] {error_msg}")
                finally:
                    # 即使出错，也要清除引用
                    self.sync_thread = None
                    print("[DEBUG] 已清除线程引用")
            
            # 确保同步引擎存在
            if not hasattr(self, 'sync_engine') or not self.sync_engine:
                print("[DEBUG] 同步引擎不存在，正在创建...")
                # 重新初始化同步引擎
                try:
                    self.sync_engine = SyncEngine()
                    print("[DEBUG] 同步引擎创建成功")
                except Exception as e:
                    error_msg = f"创建同步引擎失败: {str(e)}"
                    self._log_message(error_msg, source="find_same")
                    print(f"[DEBUG] {error_msg}")
                    self.running = False
                    self._set_buttons_state(True)
                    return
            else:
                print("[DEBUG] 同步引擎已存在")
                # 重置同步引擎状态
                try:
                    if hasattr(self.sync_engine, 'stop'):
                        self.sync_engine.stop()
                    print("[DEBUG] 同步引擎已重置")
                except Exception as e:
                    print(f"[DEBUG] 重置同步引擎时出错: {e}")
            
            # 创建并启动任务线程
            try:
                print("[DEBUG] 正在创建SyncThread...")
                print(f"[DEBUG] 线程参数: task_type=find_same, dir_a={dir_a}, dir_b={dir_b}, ignore_patterns={ignore_patterns}")
                self.sync_thread = SyncThread(
                    self.sync_engine, 
                    dir_a, 
                    dir_b, 
                    task_type="find_same",
                    ignore_patterns=ignore_patterns
                )
                print("[DEBUG] 创建SyncThread成功")
            except Exception as e:
                error_msg = f"创建线程失败: {str(e)}"
                self._log_message(error_msg, source="find_same")
                print(f"[DEBUG] {error_msg}")
                self.running = False
                self._set_buttons_state(True)
                return
            
            if PYQT_AVAILABLE:
                try:
                    print("[DEBUG] PyQt模式: 连接信号到槽")
                    # 连接信号 - 使用特定的日志处理方法
                    self.sync_thread.progress_updated.connect(lambda value: self.find_same_progress_bar.setValue(value))
                    self.sync_thread.log_updated.connect(lambda msg: self._log_message(msg, source="find_same"))
                    self.sync_thread.sync_completed.connect(self._sync_completed)
                    self.sync_thread.same_files_found.connect(self._display_same_files)
                    self.sync_thread.current_file_updated.connect(self._update_current_file)
                    print("[DEBUG] 所有信号连接完成")
                    
                    # 启动线程
                    print("[DEBUG] 启动线程...")
                    self.sync_thread.start()
                    print("[DEBUG] 线程已启动")
                except Exception as e:
                    error_msg = f"启动线程失败: {str(e)}"
                    self._log_message(error_msg, source="find_same")
                    print(f"[DEBUG] {error_msg}")
                    self.running = False
                    self._set_buttons_state(True)
            else:
                try:
                    print("[DEBUG] Tkinter模式: 设置回调函数")
                    # 设置回调 - Tkinter模式暂时保持使用默认日志
                    self.sync_thread.progress_callback = self._update_progress
                    self.sync_thread.log_callback = lambda msg: self._log_message(msg, source="find_same")
                    self.sync_thread.completed_callback = self._sync_completed
                    self.sync_thread.same_files_callback = self._display_same_files
                    self.sync_thread.current_file_callback = self._update_current_file
                    print("[DEBUG] 所有回调设置完成")
                    
                    # 启动线程
                    print("[DEBUG] 启动线程...")
                    self.sync_thread.start()
                    print("[DEBUG] 线程已启动")
                    
                    # 启动定时器更新进度和日志
                    print("[DEBUG] 启动定时器更新UI")
                    self._update_sync_ui()
                except Exception as e:
                    error_msg = f"启动线程失败: {str(e)}"
                    self._log_message(error_msg, source="find_same")
                    print(f"[DEBUG] {error_msg}")
                    self.running = False
                    self._set_buttons_state(True)
        except Exception as e:
            # 捕获所有异常，确保程序不会崩溃
            import traceback
            error_msg = f"查找相同文件过程中发生错误: {str(e)}"
            tb_str = traceback.format_exc()
            self._log_message(error_msg, source="find_same")
            self._log_message(f"错误详情: {tb_str}", source="find_same")
            print(f"[DEBUG] 严重错误: {error_msg}\n{tb_str}")
            
            # 确保状态重置
            self.running = False
            try:
                self._set_buttons_state(True)
                print("[DEBUG] 已恢复按钮状态")
            except Exception as inner_e:
                print(f"[DEBUG] 恢复按钮状态时出错: {inner_e}")
    
    def _find_duplicate_files(self):
        """开始查找重复文件"""
        directory = self.duplicate_folder_edit.text().strip() if PYQT_AVAILABLE else self.duplicate_folder_var.get().strip()
        
        if not directory or not os.path.isdir(directory):
            self._show_error("错误", "请选择有效的扫描目录")
            return
        
        # 清空重复文件列表
        self._clear_duplicate_files()
        
        # 清空日志
        self._clear_log()
        self._log_message("准备扫描重复文件...")
        
        # 设置运行状态
        self.running = True
        
        # 禁用相关按钮
        self._set_buttons_state(False)
        
        # 创建并启动扫描线程
        self.duplicate_finder_thread = DuplicateFinderThread(directory)
        
        if PYQT_AVAILABLE:
            # 连接信号
            self.duplicate_finder_thread.progress_updated.connect(lambda value: self.duplicate_progress_bar.setValue(value))
            self.duplicate_finder_thread.log_updated.connect(self._log_message)
            self.duplicate_finder_thread.duplicate_files_found.connect(self._display_duplicate_files)
            self.duplicate_finder_thread.current_file_updated.connect(self._update_duplicate_current_file)
            self.duplicate_finder_thread.finished.connect(self._on_duplicate_scan_finished)
            
            # 启动线程
            self.duplicate_finder_thread.start()
        else:
            # 设置回调
            self.duplicate_finder_thread.progress_callback = self._update_duplicate_progress
            self.duplicate_finder_thread.log_callback = self._log_message
            self.duplicate_finder_thread.duplicate_files_callback = self._display_duplicate_files
            self.duplicate_finder_thread.current_file_callback = self._update_duplicate_current_file
            
            # 启动线程
            self.duplicate_finder_thread.start()
            
            # 启动定时器更新UI
            self._update_sync_ui()
    
    def _update_duplicate_progress(self, progress):
        """更新重复文件扫描进度条"""
        if PYQT_AVAILABLE:
            self.duplicate_progress_bar.setValue(progress)
        else:
            self.duplicate_progress_bar['value'] = progress
    
    def _update_duplicate_current_file(self, file_path):
        """更新当前处理的文件"""
        if PYQT_AVAILABLE:
            self.duplicate_current_file_label.setText(f"当前文件: {os.path.basename(file_path)}")
        else:
            # 使用已存在的变量更新标签
            if hasattr(self, 'duplicate_current_file_var'):
                self.duplicate_current_file_var.set(f"当前文件: {os.path.basename(file_path)}")
            # 同时更新我们新添加的标签
            if hasattr(self, 'duplicate_current_file_label'):
                self.duplicate_current_file_label.config(text=f"当前文件: {os.path.basename(file_path)}")
    
    def _clear_duplicate_files(self):
        """清空重复文件结果"""
        if PYQT_AVAILABLE:
            self.duplicate_files_table.setRowCount(0)
        else:
            for item in self.duplicate_files_tree.get_children():
                self.duplicate_files_tree.delete(item)
    
    def _format_time(self, timestamp):
        """格式化时间戳显示"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def _display_duplicate_files(self, duplicate_groups):
        """显示重复文件扫描结果"""
        if not duplicate_groups:
            self._log_message("未找到重复文件")
            return
        
        self._log_message(f"找到 {len(duplicate_groups)} 组重复文件")
        
        if PYQT_AVAILABLE:
            # PyQt6 实现
            # 临时禁用排序以提高性能
            self.duplicate_files_table.setSortingEnabled(False)
            
            self.duplicate_files_table.setRowCount(0)
            # 设置为4列，包括保留、文件路径、文件大小和修改时间
            self.duplicate_files_table.setColumnCount(4)
            self.duplicate_files_table.setHorizontalHeaderLabels(["保留", "文件路径", "文件大小", "修改时间"])
            
            row = 0
            has_selected = False
            for group in duplicate_groups:
                size = group['size']
                files = group['files']
                
                # 默认选中除第一个文件外的所有文件
                for i, file_info in enumerate(files):
                    file_path = file_info['path']
                    modified_time = file_info['modified_time']
                    
                    # 保留列（复选框）
                    check_item = QTableWidgetItem()
                    
                    # 文件路径列
                    path_item = QTableWidgetItem(file_path)
                    
                    # 文件大小列
                    size_item = QTableWidgetItem(self._format_file_size(size))
                    # 为文件大小设置数值数据用于排序
                    size_item.setData(Qt.ItemDataRole.UserRole, size)
                    
                    # 修改时间列
                    time_item = QTableWidgetItem(self._format_time(modified_time))
                    # 为修改时间设置原始时间戳用于排序
                    time_item.setData(Qt.ItemDataRole.UserRole, modified_time)
                    
                    # 将保留列设置为复选框
                    if i > 0:
                        check_item.setCheckState(Qt.CheckState.Checked)
                        has_selected = True
                    else:
                        check_item.setCheckState(Qt.CheckState.Unchecked)
                    
                    # 添加到表格
                    self.duplicate_files_table.insertRow(row)
                    self.duplicate_files_table.setItem(row, 0, check_item)
                    self.duplicate_files_table.setItem(row, 1, path_item)
                    self.duplicate_files_table.setItem(row, 2, size_item)
                    self.duplicate_files_table.setItem(row, 3, time_item)
                    
                    row += 1
            
            # 先自动调整列宽，然后将"保留"列设置为40像素宽
            self.duplicate_files_table.resizeColumnsToContents()
            self.duplicate_files_table.horizontalHeader().resizeSection(0, 40)
            
            # 重新启用排序
            self.duplicate_files_table.setSortingEnabled(True)
            
            # 启用删除按钮
            self.delete_selected_duplicate_button.setEnabled(has_selected)
            
            # 添加选中状态变化的信号连接
            self.duplicate_files_table.itemChanged.connect(self._on_duplicate_item_changed)
            
            # 添加排序信号连接，保存和恢复选中状态
            self.duplicate_files_table.horizontalHeader().sectionClicked.connect(self._on_duplicate_table_sort)
            
            # 重新启用排序
            self.duplicate_files_table.setSortingEnabled(True)
        else:
            # Tkinter 实现
            for item in self.duplicate_files_tree.get_children():
                self.duplicate_files_tree.delete(item)
            
            self.duplicate_files_tree['columns'] = ('size',)
            self.duplicate_files_tree.column('#0', width=400, stretch=tk.YES)
            self.duplicate_files_tree.column('size', width=100, stretch=tk.NO)
            
            self.duplicate_files_tree.heading('#0', text='文件路径')
            self.duplicate_files_tree.heading('size', text='文件大小')
            
            for group in duplicate_groups:
                size = group['size']
                files = group['files']
                
                # 默认选中除第一个文件外的所有文件
                for i, file_path in enumerate(files):
                    if i > 0:
                        self.duplicate_files_tree.insert('', 'end', text=file_path, values=(self._format_file_size(size)), tags=('selected',))
                    else:
                        self.duplicate_files_tree.insert('', 'end', text=file_path, values=(self._format_file_size(size)))
            
            # 设置选中项的样式
            self.duplicate_files_tree.tag_configure('selected', background='#e6f7ff')
            
            # 启用删除按钮
            self.delete_selected_duplicate_button['state'] = 'normal'
    
    def _format_file_size(self, size):
        """格式化文件大小显示"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f'{size:.1f} {unit}'
            size /= 1024.0
        return f'{size:.1f} TB'
    
    def _show_duplicate_context_menu(self, position):
        """显示重复文件表格的右键菜单"""
        if not PYQT_AVAILABLE:
            return
        
        # 获取当前点击的单元格
        index = self.duplicate_files_table.indexAt(position)
        if not index.isValid():
            return
        
        row = index.row()
        
        # 创建右键菜单
        menu = QMenu()
        
        # 添加删除当前文件操作
        delete_action = QAction("删除此文件", self.window)
        delete_action.triggered.connect(lambda: self._delete_single_duplicate_file(row))
        menu.addAction(delete_action)
        
        # 显示菜单
        menu.exec(self.duplicate_files_table.mapToGlobal(position))
    
    def _delete_single_duplicate_file(self, row):
        """删除单个重复文件"""
        if not PYQT_AVAILABLE:
            return
        
        # 获取文件路径
        path_item = self.duplicate_files_table.item(row, 1)
        if not path_item:
            return
        
        file_path = path_item.text()
        
        # 显示确认对话框
        confirm_text = f"确定要删除文件 '{file_path}' 吗？此操作不可恢复。"
        reply = QMessageBox.question(self.window, "确认删除", confirm_text,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # 标记为选中（准备删除）
        check_item = self.duplicate_files_table.item(row, 0)
        if check_item:
            # 临时断开信号连接以避免触发不必要的更新
            self.duplicate_files_table.itemChanged.disconnect(self._on_duplicate_item_changed)
            check_item.setCheckState(Qt.CheckState.Checked)
            # 重新连接信号
            self.duplicate_files_table.itemChanged.connect(self._on_duplicate_item_changed)
        
        # 调用删除方法
        self._delete_selected_duplicate_files()
    
    def _deselect_all_duplicate_files(self):
        """取消选中所有重复文件"""
        if not PYQT_AVAILABLE:
            return
        
        # 临时断开信号连接以避免触发多次更新
        self.duplicate_files_table.itemChanged.disconnect(self._on_duplicate_item_changed)
        
        # 取消所有选中
        for row in range(self.duplicate_files_table.rowCount()):
            item = self.duplicate_files_table.item(row, 0)
            if item:
                item.setCheckState(Qt.CheckState.Unchecked)
        
        # 重新连接信号
        self.duplicate_files_table.itemChanged.connect(self._on_duplicate_item_changed)
        
        # 更新按钮状态
        self.delete_selected_duplicate_button.setEnabled(False)
        self.deselect_all_button.setEnabled(False)
    
    def _on_duplicate_scan_finished(self):
        """重复文件扫描完成后的处理"""
        self.running = False
        self._set_buttons_state(True)
        # 启用重复文件扫描特定的按钮
        if PYQT_AVAILABLE:
            self.duplicate_folder_edit.setEnabled(True)
            self.duplicate_folder_button.setEnabled(True)  # 修正按钮名称
            if self.duplicate_folder_edit.text().strip():
                self.find_duplicate_button.setEnabled(True)
        else:
            # Tkinter 部分也启用浏览按钮
            if hasattr(self, 'duplicate_folder_button'):
                self.duplicate_folder_button['state'] = 'normal'
            if hasattr(self, 'find_duplicate_button'):
                self.find_duplicate_button['state'] = 'normal' if self.duplicate_folder_var.get().strip() else 'disabled'
    
    def _on_duplicate_item_changed(self):
        """PyQt6模式下，表格项选中状态变化时更新删除按钮状态"""
        # 检查是否有选中的项
        has_selected = False
        for row in range(self.duplicate_files_table.rowCount()):
            item = self.duplicate_files_table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                has_selected = True
                break
        
        # 更新删除按钮和全不选中按钮状态
        self.delete_selected_duplicate_button.setEnabled(has_selected)
        self.deselect_all_button.setEnabled(has_selected)
    
    def _on_duplicate_table_sort(self, logical_index):
        """在排序时保持选中状态不变，并确保按文件大小和修改时间正确排序
        文件大小使用字节单位，修改时间使用时间戳进行排序"""
        # 保存选中状态
        selected_paths = set()
        for row in range(self.duplicate_files_table.rowCount()):
            item = self.duplicate_files_table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                # 现在文件路径在索引1列
                path_item = self.duplicate_files_table.item(row, 1)
                if path_item:
                    selected_paths.add(path_item.text())
        
        # 对于文件大小列（索引2），确保使用字节为单位的数值进行排序
        if logical_index == 2:  # 文件大小列
            # 获取当前排序顺序
            current_order = self.duplicate_files_table.horizontalHeader().sortIndicatorOrder()
            # 切换排序顺序
            new_order = Qt.SortOrder.DescendingOrder if current_order == Qt.SortOrder.AscendingOrder else Qt.SortOrder.AscendingOrder
            
            # 自定义排序逻辑 - 确保使用原始字节大小进行排序
            rows_with_sizes = []
            for row in range(self.duplicate_files_table.rowCount()):
                size_item = self.duplicate_files_table.item(row, 2)
                # 确保获取以字节为单位的原始文件大小
                if size_item and size_item.data(Qt.ItemDataRole.UserRole) is not None:
                    # 使用UserRole中存储的原始字节大小
                    size_in_bytes = size_item.data(Qt.ItemDataRole.UserRole)
                else:
                    # 如果没有UserRole数据，尝试从显示文本解析
                    size_text = size_item.text() if size_item else "0 B"
                    try:
                        # 解析大小文本，转换为字节
                        value_str, unit = size_text.split()
                        value = float(value_str)
                        unit = unit.upper()
                        
                        # 转换为字节
                        if unit == "B":
                            size_in_bytes = value
                        elif unit == "KB":
                            size_in_bytes = value * 1024
                        elif unit == "MB":
                            size_in_bytes = value * 1024 * 1024
                        elif unit == "GB":
                            size_in_bytes = value * 1024 * 1024 * 1024
                        elif unit == "TB":
                            size_in_bytes = value * 1024 * 1024 * 1024 * 1024
                        else:
                            size_in_bytes = 0
                    except:
                        size_in_bytes = 0
                
                rows_with_sizes.append((size_in_bytes, row))
            
            # 按照字节大小排序
            rows_with_sizes.sort(reverse=(new_order == Qt.SortOrder.DescendingOrder))
            
            # 重新排列表格内容
            self.duplicate_files_table.setSortingEnabled(False)
            
            # 创建新的数据行列表
            new_rows = []
            for _, row_idx in rows_with_sizes:
                row_data = []
                for col in range(self.duplicate_files_table.columnCount()):
                    # 注意：takeItem会从原表格中移除item
                    source_item = self.duplicate_files_table.item(row_idx, col)
                    if source_item:
                        # 创建新的item副本以保留所有属性
                        new_item = QTableWidgetItem(source_item)
                        # 复制CheckState
                        if col == 0:
                            new_item.setCheckState(source_item.checkState())
                        # 确保文件大小项保留UserRole中的原始字节大小
                        if col == 2:
                            # 确保设置正确的字节大小数据
                            size_bytes = source_item.data(Qt.ItemDataRole.UserRole)
                            if size_bytes is not None:
                                new_item.setData(Qt.ItemDataRole.UserRole, size_bytes)
                        # 确保修改时间项保留UserRole中的原始时间戳
                        elif col == 3:
                            timestamp = source_item.data(Qt.ItemDataRole.UserRole)
                            if timestamp is not None:
                                new_item.setData(Qt.ItemDataRole.UserRole, timestamp)
                        row_data.append(new_item)
                    else:
                        row_data.append(QTableWidgetItem())
                new_rows.append(row_data)
            
            # 清空表格并重新填充
            self.duplicate_files_table.setRowCount(0)
            for row_data in new_rows:
                row_position = self.duplicate_files_table.rowCount()
                self.duplicate_files_table.insertRow(row_position)
                for col, item in enumerate(row_data):
                    self.duplicate_files_table.setItem(row_position, col, item)
            
            # 更新排序指示器
            self.duplicate_files_table.horizontalHeader().setSortIndicator(logical_index, new_order)
        
        # 对于修改时间列（索引3），使用时间戳进行排序
        elif logical_index == 3:  # 修改时间列
            # 获取当前排序顺序
            current_order = self.duplicate_files_table.horizontalHeader().sortIndicatorOrder()
            # 切换排序顺序
            new_order = Qt.SortOrder.DescendingOrder if current_order == Qt.SortOrder.AscendingOrder else Qt.SortOrder.AscendingOrder
            
            # 自定义排序逻辑 - 使用时间戳进行排序
            rows_with_timestamps = []
            for row in range(self.duplicate_files_table.rowCount()):
                time_item = self.duplicate_files_table.item(row, 3)
                # 获取时间戳
                if time_item and time_item.data(Qt.ItemDataRole.UserRole) is not None:
                    timestamp = time_item.data(Qt.ItemDataRole.UserRole)
                else:
                    # 默认时间戳为0
                    timestamp = 0
                
                rows_with_timestamps.append((timestamp, row))
            
            # 按照时间戳排序
            rows_with_timestamps.sort(reverse=(new_order == Qt.SortOrder.DescendingOrder))
            
            # 重新排列表格内容
            self.duplicate_files_table.setSortingEnabled(False)
            
            # 创建新的数据行列表
            new_rows = []
            for _, row_idx in rows_with_timestamps:
                row_data = []
                for col in range(self.duplicate_files_table.columnCount()):
                    # 注意：takeItem会从原表格中移除item
                    source_item = self.duplicate_files_table.item(row_idx, col)
                    if source_item:
                        # 创建新的item副本以保留所有属性
                        new_item = QTableWidgetItem(source_item)
                        # 复制CheckState
                        if col == 0:
                            new_item.setCheckState(source_item.checkState())
                        # 确保文件大小项保留UserRole中的原始字节大小
                        if col == 2:
                            size_bytes = source_item.data(Qt.ItemDataRole.UserRole)
                            if size_bytes is not None:
                                new_item.setData(Qt.ItemDataRole.UserRole, size_bytes)
                        # 确保修改时间项保留UserRole中的原始时间戳
                        elif col == 3:
                            timestamp = source_item.data(Qt.ItemDataRole.UserRole)
                            if timestamp is not None:
                                new_item.setData(Qt.ItemDataRole.UserRole, timestamp)
                        row_data.append(new_item)
                    else:
                        row_data.append(QTableWidgetItem())
                new_rows.append(row_data)
            
            # 清空表格并重新填充
            self.duplicate_files_table.setRowCount(0)
            for row_data in new_rows:
                row_position = self.duplicate_files_table.rowCount()
                self.duplicate_files_table.insertRow(row_position)
                for col, item in enumerate(row_data):
                    self.duplicate_files_table.setItem(row_position, col, item)
            
            # 更新排序指示器
            self.duplicate_files_table.horizontalHeader().setSortIndicator(logical_index, new_order)
        else:
            # 对于其他列，使用默认排序
            self.duplicate_files_table.sortItems(logical_index)
            QApplication.processEvents()
        
        # 重新设置保留列宽度，确保排序后不会改变宽度
        self.duplicate_files_table.horizontalHeader().resizeSection(0, 40)
        
        # 恢复选中状态
        for row in range(self.duplicate_files_table.rowCount()):
            # 文件路径在索引1列
            path_item = self.duplicate_files_table.item(row, 1)
            if path_item and path_item.text() in selected_paths:
                check_item = self.duplicate_files_table.item(row, 0)
                if check_item:
                    # 临时断开信号连接以避免触发不必要的更新
                    self.duplicate_files_table.itemChanged.disconnect(self._on_duplicate_item_changed)
                    check_item.setCheckState(Qt.CheckState.Checked)
                    # 重新连接信号
                    self.duplicate_files_table.itemChanged.connect(self._on_duplicate_item_changed)
    
    def _delete_selected_duplicate_files(self):
        """删除选中的重复文件"""
        selected_files = []
        
        if PYQT_AVAILABLE:
            # 获取PyQt6中选中的文件
            for row in range(self.duplicate_files_table.rowCount()):
                item = self.duplicate_files_table.item(row, 0)
                if item and item.checkState() == Qt.CheckState.Checked:
                    # 文件路径实际在索引1列
                    path_item = self.duplicate_files_table.item(row, 1)
                    if path_item:
                        file_path = path_item.text()
                        selected_files.append(file_path)
        else:
            # 获取Tkinter中选中的文件
            for item in self.duplicate_files_tree.get_children():
                if self.duplicate_files_tree.tag_has('selected', item):
                    file_path = self.duplicate_files_tree.item(item, 'text')
                    selected_files.append(file_path)
        
        if not selected_files:
            self._show_error("提示", "请先选择要删除的文件")
            return
        
        # 显示确认对话框
        file_count = len(selected_files)
        confirm_text = f"确定要删除选中的 {file_count} 个文件吗？此操作不可恢复。"
        
        if PYQT_AVAILABLE:
            reply = QMessageBox.question(self.window, "确认删除", confirm_text, 
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return
        else:
            # Tkinter确认对话框
            from tkinter import messagebox
            if not messagebox.askyesno("确认删除", confirm_text):
                return
        
        self._log_message(f"开始删除 {file_count} 个文件...")
        
        # 执行删除操作
        deleted_count = 0
        failed_count = 0
        failed_files = []
        
        for file_path in selected_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_count += 1
                    self._log_message(f"已删除: {file_path}")
                    # 从UI中移除已删除的文件
                    if PYQT_AVAILABLE:
                        for row in range(self.duplicate_files_table.rowCount()):
                            # 文件路径实际在索引1列
                            path_item = self.duplicate_files_table.item(row, 1)
                            if path_item and path_item.text() == file_path:
                                self.duplicate_files_table.removeRow(row)
                                break
                    else:
                        for item in self.duplicate_files_tree.get_children():
                            if self.duplicate_files_tree.item(item, 'text') == file_path:
                                self.duplicate_files_tree.delete(item)
                                break
            except Exception as e:
                failed_count += 1
                failed_files.append(f"{file_path}: {str(e)}")
                self._log_message(f"删除失败: {file_path}, 错误: {str(e)}")
        
        # 显示删除结果
        result_text = f"删除完成: 成功 {deleted_count} 个，失败 {failed_count} 个"
        self._log_message(result_text)
        
        if PYQT_AVAILABLE:
            QMessageBox.information(self.window, "删除结果", result_text)
        else:
            messagebox.showinfo("删除结果", result_text)
        
        if failed_files:
            failed_text = "\n".join(failed_files)
            self._log_message(f"失败文件列表:\n{failed_text}")
    
    def _display_same_files(self, same_files):
        """显示找到的相同文件"""
        if PYQT_AVAILABLE:
            # 清空表格
            self.find_same_files_table.setRowCount(0)
            
            # 添加数据
            for i, (file_a, file_b) in enumerate(same_files):
                self.find_same_files_table.insertRow(i)
                
                # 添加文件路径
                self.find_same_files_table.setItem(i, 0, QTableWidgetItem(file_a))
                self.find_same_files_table.setItem(i, 1, QTableWidgetItem(file_b))
                
                # 添加删除按钮组
                button_widget = QWidget()
                layout = QHBoxLayout(button_widget)
                layout.setContentsMargins(2, 2, 2, 2)
                
                # 删除源文件按钮
                delete_a_btn = QPushButton("删除A")
                delete_a_btn.setToolTip(f"删除源文件: {file_a}")
                delete_a_btn.setProperty("file_a", file_a)
                delete_a_btn.setProperty("file_b", file_b)
                delete_a_btn.setProperty("delete_type", "a")
                delete_a_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="a": self._delete_file(a, b, t))
                layout.addWidget(delete_a_btn)
                
                # 删除目标文件按钮
                delete_b_btn = QPushButton("删除B")
                delete_b_btn.setToolTip(f"删除目标文件: {file_b}")
                delete_b_btn.setProperty("file_a", file_a)
                delete_b_btn.setProperty("file_b", file_b)
                delete_b_btn.setProperty("delete_type", "b")
                delete_b_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="b": self._delete_file(a, b, t))
                layout.addWidget(delete_b_btn)
                
                # 删除全部按钮
                delete_all_btn = QPushButton("删除全部")
                delete_all_btn.setToolTip(f"同时删除两个文件")
                delete_all_btn.setProperty("file_a", file_a)
                delete_all_btn.setProperty("file_b", file_b)
                delete_all_btn.setProperty("delete_type", "all")
                delete_all_btn.clicked.connect(lambda checked, a=file_a, b=file_b, t="all": self._delete_file(a, b, t))
                layout.addWidget(delete_all_btn)
                
                self.find_same_files_table.setCellWidget(i, 2, button_widget)
        else:
            # 清空树形视图
            for item in self.same_files_tree.get_children():
                self.same_files_tree.delete(item)
            
            # 添加数据
            for i, (file_a, file_b) in enumerate(same_files):
                item_id = self.same_files_tree.insert('', tk.END, values=(file_a, file_b, "删除"))
                
                # 为每个项目添加绑定删除功能的按钮（简化处理，通过选中后点击删除按钮）
        
        self._log_message(f"找到 {len(same_files)} 对相同文件", source="find_same")
        self._set_status(f"找到 {len(same_files)} 对相同文件")
    
    def _clear_same_files(self):
        """清空相同文件列表"""
        if PYQT_AVAILABLE:
            self.find_same_files_table.setRowCount(0)
        else:
            for item in self.same_files_tree.get_children():
                self.same_files_tree.delete(item)
    
    def _delete_file(self, file_a, file_b, delete_type="all"):
        """删除指定的文件
        
        Args:
            file_a: 源文件路径
            file_b: 目标文件路径
            delete_type: 删除类型，"a"表示只删除源文件，"b"表示只删除目标文件，"all"表示删除两个文件
        """
        # 根据删除类型构建确认消息
        if delete_type == "a":
            message = f"确定要删除源文件吗？\n{file_a}"
        elif delete_type == "b":
            message = f"确定要删除目标文件吗？\n{file_b}"
        else:
            message = f"确定要删除这两个文件吗？\n{file_a}\n{file_b}"
        
        # 显示确认对话框
        confirmed = False
        if PYQT_AVAILABLE:
            reply = QMessageBox.question(
                self.window, 
                "确认删除", 
                message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            confirmed = reply == QMessageBox.StandardButton.Yes
        else:
            confirmed = tk.messagebox.askyesno(
                "确认删除",
                message
            )
        
        if confirmed:
            try:
                # 根据删除类型删除文件
                if delete_type in ["a", "all"] and os.path.exists(file_a):
                    os.remove(file_a)
                    self._log_message(f"已删除源文件: {file_a}")
                if delete_type in ["b", "all"] and os.path.exists(file_b):
                    os.remove(file_b)
                    self._log_message(f"已删除目标文件: {file_b}")
                
                # 从列表中移除
                if PYQT_AVAILABLE:
                    # 查找并删除行
                    for row in range(self.find_same_files_table.rowCount()):
                        if (self.find_same_files_table.item(row, 0).text() == file_a and 
                            self.find_same_files_table.item(row, 1).text() == file_b):
                            self.find_same_files_table.removeRow(row)
                            break
                else:
                    # 查找并删除项
                    for item in self.same_files_tree.get_children():
                        values = self.same_files_tree.item(item, "values")
                        if values[0] == file_a and values[1] == file_b:
                            self.same_files_tree.delete(item)
                            break
                
                # 更新状态
                if delete_type == "a":
                    self._set_status("已删除源文件")
                elif delete_type == "b":
                    self._set_status("已删除目标文件")
                else:
                    self._set_status("已同时删除两个文件")
            except Exception as e:
                self._show_error("删除失败", f"删除文件时发生错误: {str(e)}")
    
    def _delete_selected_files(self, which=None):
        """删除选中的文件，添加确认机制并显示文件名"""
        if PYQT_AVAILABLE:
            selected_rows = set()
            for item in self.find_same_files_table.selectedItems():
                selected_rows.add(item.row())
            
            if not selected_rows:
                self._show_error("提示", "请先选择要删除的文件")
                return
            
            # 如果传入了which参数，则直接使用该参数作为删除类型
            if which in ["a", "b", "both"]:
                delete_type = which if which != "both" else "all"
                
                # 构建要删除的文件列表
                files_to_delete = []
                for row in selected_rows:
                    file_a = self.find_same_files_table.item(row, 0).text()
                    file_b = self.find_same_files_table.item(row, 1).text()
                    if delete_type in ["a", "all"] and os.path.exists(file_a):
                        files_to_delete.append(f"[文件夹A] {os.path.basename(file_a)}")
                    if delete_type in ["b", "all"] and os.path.exists(file_b):
                        files_to_delete.append(f"[文件夹B] {os.path.basename(file_b)}")
                
                # 构建确认消息
                delete_type_text = {
                    "a": "文件夹A中的文件",
                    "b": "文件夹B中的文件",
                    "all": "所有选中的文件"
                }
                
                confirm_msg = f"确定要删除{delete_type_text.get(delete_type, '')}吗？\n\n"
                confirm_msg += "\n".join(files_to_delete[:10])  # 只显示前10个文件
                if len(files_to_delete) > 10:
                    confirm_msg += f"\n... 以及其他 {len(files_to_delete) - 10} 个文件"
                
                reply = QMessageBox.question(
                    self.window, 
                    "确认删除", 
                    confirm_msg, 
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply != QMessageBox.StandardButton.Yes:
                    return  # 用户取消删除
                
                proceed_with_delete = True
            else:
                # 创建选择删除类型的对话框
                delete_dialog = QDialog(self.window)
                delete_dialog.setWindowTitle("选择删除类型")
                delete_dialog.resize(300, 150)
                
                layout = QVBoxLayout(delete_dialog)
                
                label = QLabel(f"请选择要删除的 {len(selected_rows)} 对文件的删除方式：")
                layout.addWidget(label)
                
                delete_type_group = QGroupBox()
                delete_type_layout = QVBoxLayout(delete_type_group)
                
                button_group = QButtonGroup(delete_dialog)
                
                radio_a = QRadioButton("只删除源文件(A)")
                radio_b = QRadioButton("只删除目标文件(B)")
                radio_all = QRadioButton("同时删除源文件和目标文件")
                radio_all.setChecked(True)  # 默认同时删除
                
                button_group.addButton(radio_a)
                button_group.addButton(radio_b)
                button_group.addButton(radio_all)
                
                delete_type_layout.addWidget(radio_a)
                delete_type_layout.addWidget(radio_b)
                delete_type_layout.addWidget(radio_all)
                
                layout.addWidget(delete_type_group)
                
                buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
                buttons.accepted.connect(delete_dialog.accept)
                buttons.rejected.connect(delete_dialog.reject)
                
                layout.addWidget(buttons)
                
                if delete_dialog.exec() == QDialog.DialogCode.Accepted:
                    # 确定删除类型
                    if radio_a.isChecked():
                        delete_type = "a"
                    elif radio_b.isChecked():
                        delete_type = "b"
                    else:
                        delete_type = "all"
                    
                    # 构建要删除的文件列表
                    files_to_delete = []
                    for row in selected_rows:
                        file_a = self.find_same_files_table.item(row, 0).text()
                        file_b = self.find_same_files_table.item(row, 1).text()
                        if delete_type in ["a", "all"] and os.path.exists(file_a):
                            files_to_delete.append(f"[文件夹A] {os.path.basename(file_a)}")
                        if delete_type in ["b", "all"] and os.path.exists(file_b):
                            files_to_delete.append(f"[文件夹B] {os.path.basename(file_b)}")
                    
                    # 显示确认对话框，列出要删除的文件
                    confirm_msg = f"确定要删除以下 {len(files_to_delete)} 个文件吗？\n\n"
                    confirm_msg += "\n".join(files_to_delete[:10])  # 只显示前10个文件
                    if len(files_to_delete) > 10:
                        confirm_msg += f"\n... 以及其他 {len(files_to_delete) - 10} 个文件"
                    
                    reply = QMessageBox.question(
                        self.window, 
                        "确认删除", 
                        confirm_msg, 
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        proceed_with_delete = True
                    else:
                        return  # 用户取消删除
                else:
                    return  # 用户取消删除
            
            # 反向遍历删除行，避免索引变化问题
            success_count = 0
            fail_count = 0
            
            for row in sorted(selected_rows, reverse=True):
                file_a = self.find_same_files_table.item(row, 0).text()
                file_b = self.find_same_files_table.item(row, 1).text()
                
                try:
                    # 根据删除类型删除文件
                    if delete_type in ["a", "all"] and os.path.exists(file_a):
                        os.remove(file_a)
                        self._log_message(f"已删除文件: {file_a}", source="find_same")
                    if delete_type in ["b", "all"] and os.path.exists(file_b):
                        os.remove(file_b)
                        self._log_message(f"已删除文件: {file_b}", source="find_same")
                    
                    self.find_same_files_table.removeRow(row)
                    success_count += 1
                except Exception as e:
                    self._log_message(f"删除文件失败: {str(e)}", source="find_same")
                    fail_count += 1
            
            # 记录日志
            self._log_message(f"删除操作完成：成功 {success_count} 项，失败 {fail_count} 项", source="find_same")
            self._set_status(f"删除操作完成：成功 {success_count} 项，失败 {fail_count} 项")
        else:
            selected_items = self.same_files_tree.selection()
            
            if not selected_items:
                tk.messagebox.showerror("提示", "请先选择要删除的文件")
                return
            
            # 构建要删除的文件列表
            files_to_delete = []
            for item in selected_items:
                file_a, file_b, _ = self.same_files_tree.item(item, "values")
                if os.path.exists(file_a):
                    files_to_delete.append(f"[文件夹A] {os.path.basename(file_a)}")
                if os.path.exists(file_b):
                    files_to_delete.append(f"[文件夹B] {os.path.basename(file_b)}")
            
            # 构建确认消息
            confirm_msg = f"确定要删除以下 {len(files_to_delete)} 个文件吗？\n\n"
            confirm_msg += "\n".join(files_to_delete[:10])  # 只显示前10个文件
            if len(files_to_delete) > 10:
                confirm_msg += f"\n... 以及其他 {len(files_to_delete) - 10} 个文件"
            
            # 显示确认对话框
            confirmed = tk.messagebox.askyesno(
                "确认删除",
                confirm_msg
            )
            
            if confirmed:
                for item in selected_items:
                    file_a, file_b, _ = self.same_files_tree.item(item, "values")
                    
                    try:
                        if os.path.exists(file_a):
                            os.remove(file_a)
                            self._log_message(f"已删除文件: {file_a}", source="find_same")
                        if os.path.exists(file_b):
                            os.remove(file_b)
                            self._log_message(f"已删除文件: {file_b}", source="find_same")
                        
                        self.same_files_tree.delete(item)
                    except Exception as e:
                        self._log_message(f"删除文件失败: {str(e)}", source="find_same")
    
    def _update_sync_ui(self):
        """更新同步UI（Tkinter模式）"""
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.update_progress()
            self.root.after(100, self._update_sync_ui)
    
    def _pause_sync(self):
        """暂停同步"""
        if self.sync_engine:
            if self.sync_engine.is_paused():
                self.sync_engine.resume()
                if PYQT_AVAILABLE:
                    self.pause_btn.setText("暂停")
                else:
                    self.pause_btn.config(text="暂停")
            else:
                self.sync_engine.pause()
                if PYQT_AVAILABLE:
                    self.pause_btn.setText("恢复")
                else:
                    self.pause_btn.config(text="恢复")
    
    def _stop_sync(self):
        """停止同步"""
        if self.sync_thread:
            # 停止线程
            self.sync_thread.stop()
        if self.sync_engine:
            self.sync_engine.stop()
        # 重置运行状态
        self.running = False
        # 重置按钮状态
        self._set_buttons_state(True)
    
    def _sync_completed(self, success):
        """同步或查找完成处理"""
        # 重置运行状态
        self.running = False
        
        # 重置按钮状态
        self._set_buttons_state(True)
        
        # 更新状态
        if success:
            self._set_status("操作完成")
            # 同步完成后，自动刷新比对显示（默认显示不同的文件/文件夹）
            if PYQT_AVAILABLE:
                folder_a = self.sync_folder_a_edit.text().strip()
                folder_b = self.sync_folder_b_edit.text().strip()
                if folder_a and folder_b and os.path.isdir(folder_a) and os.path.isdir(folder_b):
                    # 确保"只显示不同文件"选项被选中
                    if hasattr(self, 'only_show_diff_files'):
                        self.only_show_diff_files.setChecked(True)
                    # 刷新差异显示
                    self._auto_compare_if_ready(force=True)
        else:
            self._set_status("操作失败")
        
        # 重置进度条
        if PYQT_AVAILABLE:
            self.sync_progress_bar.setValue(0)
            self.find_same_progress_bar.setValue(0)
        else:
            self._update_progress(0)
        
        # 安全清理线程资源
        self._cleanup_thread_resources()
        
    def _cleanup_thread_resources(self):
        """安全清理线程资源"""
        print("[DEBUG] 开始执行_cleanup_thread_resources")
        thread_attributes = ['sync_thread', 'same_files_thread', 'duplicate_finder_thread', 'file_slimming_thread']
        
        try:
            for attr_name in thread_attributes:
                print(f"[DEBUG] 开始清理线程属性: {attr_name}")
                
                # 检查线程是否存在
                if hasattr(self, attr_name) and getattr(self, attr_name) is not None:
                    thread = getattr(self, attr_name)
                    print(f"[DEBUG] 找到线程: {attr_name}")
                    
                    # 先尝试安全停止线程
                    if hasattr(thread, 'stop'):
                        try:
                            print(f"[DEBUG] 调用线程 {attr_name} 的stop方法")
                            thread.stop()
                            print(f"[DEBUG] 线程 {attr_name} 停止方法调用成功")
                        except Exception as e:
                            print(f"[DEBUG] 调用线程 {attr_name} stop方法异常: {e}")
                    
                    # 断开所有信号连接
                    signals_to_disconnect = ['progress_updated', 'log_updated', 'sync_completed', 
                                            'same_files_found', 'current_file_updated', 'slimming_completed',
                                            'duplicates_found', 'scan_progress']
                    
                    for signal_name in signals_to_disconnect:
                        try:
                            if hasattr(thread, signal_name):
                                signal = getattr(thread, signal_name)
                                if hasattr(signal, 'disconnect'):
                                    signal.disconnect()
                                    print(f"[DEBUG] 线程 {attr_name} 断开信号 {signal_name} 成功")
                        except Exception as e:
                            print(f"[DEBUG] 线程 {attr_name} 断开信号 {signal_name} 异常: {e}")
                    
                    # 等待线程完全终止
                    if hasattr(thread, 'wait') and hasattr(thread, 'isRunning'):
                        try:
                            if thread.isRunning():
                                print(f"[DEBUG] 等待线程 {attr_name} 完成...")
                                # 分多次等待，增加超时处理
                                wait_time = 500
                                total_wait = 0
                                max_wait = 3000  # 最多等待3秒
                                
                                while thread.isRunning() and total_wait < max_wait:
                                    thread.wait(wait_time)
                                    total_wait += wait_time
                                    print(f"[DEBUG] 线程 {attr_name} 等待中，已等待: {total_wait}ms")
                                
                                # 如果线程仍在运行，尝试强制终止
                                if hasattr(thread, 'terminate') and thread.isRunning():
                                    try:
                                        print(f"[DEBUG] 线程 {attr_name} 仍在运行，尝试强制终止")
                                        thread.terminate()
                                        print(f"[DEBUG] 线程 {attr_name} 强制终止命令已发出")
                                        # 再等待一下确保终止
                                        thread.wait(1000)
                                    except Exception as e:
                                        print(f"[DEBUG] 强制终止线程 {attr_name} 异常: {e}")
                                
                                print(f"[DEBUG] 线程 {attr_name} 等待完成，总等待时间: {total_wait}ms")
                        except Exception as e:
                            print(f"[DEBUG] 等待线程 {attr_name} 完成异常: {e}")
                    
                    # 清理线程引用，让垃圾回收可以回收
                    print(f"[DEBUG] 删除线程 {attr_name} 引用")
                    setattr(self, attr_name, None)
                    print(f"[DEBUG] 线程 {attr_name} 引用已设为None")
            
            print("[DEBUG] 所有线程资源清理完成")
        except Exception as e:
            print(f"[DEBUG] 线程资源清理过程异常: {e}")
            import traceback
            print(f"[DEBUG] 异常堆栈:\n{traceback.format_exc()}")
        finally:
            print("[DEBUG] _cleanup_thread_resources 执行完成")
    
    def _update_progress(self, value):
        """更新进度条"""
        if PYQT_AVAILABLE:
            self.progress_bar.setValue(value)
            # 同时更新相同文件比对页面的进度条
            self.find_same_progress_bar.setValue(value)
        else:
            self.progress_var.set(value)
    
    def _log_message(self, message, source="sync"):
        """记录日志消息
        
        Args:
            message: 日志消息内容
            source: 日志来源，"sync"表示同步日志，"find_same"表示相同文件比对日志
        """
        if PYQT_AVAILABLE:
            # 根据来源选择不同的日志组件
            if source == "find_same" and hasattr(self, 'find_same_log_text'):
                self.find_same_log_text.append(message)
                # 自动滚动到底部
                self.find_same_log_text.moveCursor(QTextCursor.MoveOperation.End)
            else:
                # 默认使用同步日志
                self.sync_log_text.append(message)
                # 自动滚动到底部
                self.sync_log_text.moveCursor(QTextCursor.MoveOperation.End)
        else:
            # Tkinter界面暂时只支持默认日志
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
    
    def _clear_log(self):
        """清空日志"""
        if PYQT_AVAILABLE:
            self.sync_log_text.clear()
        else:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)
    
    def _clear_find_same_log(self):
        """清空相同文件比对日志"""
        if PYQT_AVAILABLE and hasattr(self, 'find_same_log_text'):
            self.find_same_log_text.clear()
    
    def _update_current_file(self, file_path):
        """更新当前正在处理的文件显示"""
        # 在状态栏显示当前正在扫描的文件
        self._set_status(f"正在扫描: {os.path.basename(file_path)}")
    
    def _set_status(self, status):
        """设置状态栏文本"""
        if PYQT_AVAILABLE:
            self.status_bar.showMessage(status)
        else:
            self.status_var.set(status)
    
    def _set_buttons_state(self, enabled):
        """设置按钮状态"""
        if PYQT_AVAILABLE:
            # 获取当前Tab
            current_tab = self.tab_widget.currentIndex()
            
            # 根据当前Tab设置按钮状态
            if current_tab == 0:  # 同步页面
                self.start_btn.setEnabled(enabled)
                self.pause_btn.setEnabled(not enabled)
                self.stop_btn.setEnabled(not enabled)
                
                if not enabled:
                    self.pause_btn.setText("暂停")
            elif current_tab == 1:  # 相同文件比对页面
                self.find_same_files_btn.setEnabled(enabled)
            else:  # 重复文件查找页面
                if hasattr(self, 'find_duplicate_button'):
                    # 确保参数类型为布尔值
                    folder_valid = False
                    if hasattr(self, 'duplicate_folder_edit'):
                        folder_valid = bool(self.duplicate_folder_edit.text().strip())
                    self.find_duplicate_button.setEnabled(enabled and folder_valid)
            
            # 根据当前Tab更新相应的删除按钮状态
            if hasattr(self, 'delete_selected_a_button') and hasattr(self, 'delete_selected_b_button') and hasattr(self, 'delete_selected_both_button'):
                # 同步页面的删除按钮
                has_selection = False
                if hasattr(self, 'find_same_files_table'):
                    for item in self.find_same_files_table.selectedItems():
                        has_selection = True
                        break
                self.delete_selected_a_button.setEnabled(enabled)
                self.delete_selected_b_button.setEnabled(enabled)
                self.delete_selected_both_button.setEnabled(enabled)
        else:
            is_sync_task = self.task_type_var.get() == "sync"
            state = tk.NORMAL if enabled else tk.DISABLED
            self.start_btn.config(state=tk.NORMAL if (enabled and is_sync_task) else tk.DISABLED)
            self.find_same_files_btn.config(state=tk.NORMAL if (enabled and not is_sync_task) else tk.DISABLED)
            self.pause_btn.config(state=not state)
            self.stop_btn.config(state=not state)
            
            if not enabled:
                self.pause_btn.config(text="暂停")
    
    def _show_error(self, title, message):
        """显示错误消息"""
        if PYQT_AVAILABLE:
            QMessageBox.critical(self.window, title, message)
        else:
            tk.messagebox.showerror(title, message)
    
    def _show_info(self, title, message):
        """显示信息对话框"""
        if PYQT_AVAILABLE:
            QMessageBox.information(self.window, title, message)
        else:
            tk.messagebox.showinfo(title, message)
    
    def set_sync_engine(self, sync_engine):
        """设置同步引擎"""
        self.sync_engine = sync_engine
    
    def _show_source_context_menu(self, position, tab="sync"):
        """显示源文件夹的右键菜单"""
        import traceback
        try:
            # 导入需要的模块
            from PyQt6.QtWidgets import QMessageBox
            
            # 检查PyQt是否可用
            if QFileSystemModel is None or not PYQT_AVAILABLE:
                self._log_message(f"PyQt组件不可用，无法显示右键菜单", source="sync")
                return
            
            # 确保在主线程中访问UI组件
            app = QApplication.instance()
            if not app:
                self._log_message(f"无法获取QApplication实例", source="sync")
                return
            
            # 根据tab参数选择对应的tree和model
            tree = None
            model = None
            source_model = None
            use_proxy = False
            
            try:
                if tab == "sync":
                    # 安全获取tree控件
                    if not hasattr(self, 'sync_source_tree') or self.sync_source_tree is None:
                        self._log_message(f"sync_source_tree组件不存在", source="sync")
                        return
                    tree = self.sync_source_tree
                    
                    # 检查是否使用了代理模型（差异文件显示模式）
                    current_model = tree.model()
                    if hasattr(self, 'source_diff_proxy') and current_model == self.source_diff_proxy:
                        model = self.source_diff_proxy
                        source_model = self.sync_source_model
                        use_proxy = True
                    elif hasattr(self, 'sync_source_model'):
                        model = self.sync_source_model
                        use_proxy = False
                    else:
                        self._log_message(f"无法获取有效的文件系统模型", source="sync")
                        return
                elif tab == "find_same":
                    if hasattr(self, 'find_same_source_tree') and self.find_same_source_tree is not None:
                        tree = self.find_same_source_tree
                    else:
                        self._log_message(f"find_same_source_tree组件不存在", source="sync")
                        return
                    if hasattr(self, 'find_same_source_model'):
                        model = self.find_same_source_model
                    else:
                        self._log_message(f"find_same_source_model不存在", source="sync")
                        return
                else:
                    # 默认使用sync视图的组件
                    if not hasattr(self, 'sync_source_tree') or self.sync_source_tree is None:
                        self._log_message(f"sync_source_tree组件不存在", source="sync")
                        return
                    tree = self.sync_source_tree
                    
                    current_model = tree.model()
                    if hasattr(self, 'source_diff_proxy') and current_model == self.source_diff_proxy:
                        model = self.source_diff_proxy
                        source_model = self.sync_source_model
                        use_proxy = True
                    elif hasattr(self, 'sync_source_model'):
                        model = self.sync_source_model
                        use_proxy = False
                    else:
                        self._log_message(f"无法获取有效的文件系统模型", source="sync")
                        return
                
                # 安全检查：确保tree和model不为None
                if not tree or not model:
                    self._log_message(f"找不到tree或model组件", source="sync")
                    return
                
                # 创建右键菜单
                try:
                    # 不依赖self.window，使用tree作为父组件
                    menu = QMenu(tree)
                except Exception as e:
                    self._log_message(f"创建右键菜单失败: {str(e)}", source="sync")
                    logging.error(f"创建右键菜单失败详情: {traceback.format_exc()}")
                    return
                
                # 获取选中的索引（创建副本避免后续操作影响）
                try:
                    selection_model = tree.selectionModel()
                    selected_indices = []
                    if selection_model:
                        selected_indices = list(selection_model.selectedRows())
                        
                        # 只有在sync标签页才显示复制到右侧的选项
                        if tab == "sync" and selected_indices:
                            try:
                                copy_to_right_action = QAction("复制到右侧文件夹", tree)
                                # 创建索引副本，避免闭包引用问题
                                indices_copy = selected_indices.copy()
                                # 使用lambda时捕获当前值
                                def on_copy_action_triggered(checked, idx=indices_copy, dir="right", mdl=model):
                                    try:
                                        self._copy_selected_files(idx, dir, mdl)
                                    except Exception as inner_e:
                                        error_msg = f"执行复制操作时出错: {str(inner_e)}"
                                        self._log_message(error_msg, source="sync")
                                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                                        try:
                                            QMessageBox.critical(app.activeWindow(), "错误", error_msg)
                                        except:
                                            pass
                                
                                copy_to_right_action.triggered.connect(on_copy_action_triggered)
                                menu.addAction(copy_to_right_action)
                            except Exception as e:
                                error_msg = f"添加复制菜单项失败: {str(e)}"
                                self._log_message(error_msg, source="sync")
                                logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                except Exception as e:
                    error_msg = f"获取选中索引时出错: {str(e)}"
                    self._log_message(error_msg, source="sync")
                    logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                
                # 获取当前位置的索引
                try:
                    index = tree.indexAt(position)
                    if index.isValid():
                        try:
                            # 如果使用代理模型，需要转换为源模型索引
                            if use_proxy and source_model:
                                source_index = model.mapToSource(index)
                                if not source_index.isValid():
                                    self._log_message("无法转换为源模型索引", source="sync")
                                    # 继续执行，不返回，避免菜单无法显示其他选项
                                else:
                                    file_path = source_model.filePath(source_index)
                            else:
                                # 直接使用原始模型
                                file_path = model.filePath(index)
                            
                            # 检查是否是目录
                            if os.path.isdir(file_path):
                                set_as_source_action = QAction("设为文件夹A", tree)
                                # 使用lambda时捕获当前值
                                def on_set_source_action_triggered(checked, path=file_path, t=tab):
                                    try:
                                        self._set_as_source_folder(path, tab=t)
                                    except Exception as inner_e:
                                        error_msg = f"设置文件夹A时出错: {str(inner_e)}"
                                        self._log_message(error_msg, source="sync")
                                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                                        try:
                                            QMessageBox.critical(app.activeWindow(), "错误", error_msg)
                                        except:
                                            pass
                                
                                set_as_source_action.triggered.connect(on_set_source_action_triggered)
                                menu.addAction(set_as_source_action)
                        except Exception as e:
                            error_msg = f"处理文件路径时出错: {str(e)}"
                            self._log_message(error_msg, source="sync")
                            logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                except Exception as e:
                    error_msg = f"获取索引信息时出错: {str(e)}"
                    self._log_message(error_msg, source="sync")
                    logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                
                # 显示菜单（如果有菜单项）
                if menu.actions():
                    try:
                        # 使用viewport的mapToGlobal方法来正确定位菜单
                        menu.exec(tree.viewport().mapToGlobal(position))
                    except Exception as e:
                        error_msg = f"显示右键菜单时出错: {str(e)}"
                        self._log_message(error_msg, source="sync")
                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                
            except Exception as e:
                error_msg = f"设置tree和model时出错: {str(e)}"
                self._log_message(error_msg, source="sync")
                logging.error(f"{error_msg}详情: {traceback.format_exc()}")
        except Exception as e:
            error_msg = f"显示源文件夹右键菜单时出错: {str(e)}"
            self._log_message(error_msg, source="sync")
            logging.error(f"右键菜单错误详情: {traceback.format_exc()}")
            try:
                if PYQT_AVAILABLE:
                    QMessageBox.critical(getattr(self, 'window', None), "错误", f"右键菜单操作失败: {str(e)}")
            except:
                pass
    
    def _show_target_context_menu(self, position, tab=None):
        """显示目标文件夹的右键菜单"""
        import traceback
        try:
            # 导入需要的模块
            from PyQt6.QtWidgets import QMessageBox
            
            # 检查PyQt是否可用
            if QFileSystemModel is None or not PYQT_AVAILABLE:
                self._log_message(f"PyQt组件不可用，无法显示右键菜单", source="sync")
                return
            
            # 确保在主线程中访问UI组件
            app = QApplication.instance()
            if not app:
                self._log_message(f"无法获取QApplication实例", source="sync")
                return
            
            # 根据tab参数选择正确的tree和model
            tree = None
            model = None
            source_model = None
            use_proxy = False
            
            try:
                if tab == "sync":
                    # 安全获取tree控件
                    if not hasattr(self, 'sync_target_tree') or self.sync_target_tree is None:
                        self._log_message(f"sync_target_tree组件不存在", source="sync")
                        return
                    tree = self.sync_target_tree
                    
                    # 检查是否使用了代理模型（差异文件显示模式）
                    current_model = tree.model()
                    if hasattr(self, 'target_diff_proxy') and current_model == self.target_diff_proxy:
                        model = self.target_diff_proxy
                        source_model = self.sync_target_model
                        use_proxy = True
                    elif hasattr(self, 'sync_target_model'):
                        model = self.sync_target_model
                        use_proxy = False
                    else:
                        self._log_message(f"无法获取有效的文件系统模型", source="sync")
                        return
                elif tab == "find_same":
                    if hasattr(self, 'find_same_target_tree') and self.find_same_target_tree is not None:
                        tree = self.find_same_target_tree
                    else:
                        self._log_message(f"find_same_target_tree组件不存在", source="sync")
                        return
                    if hasattr(self, 'find_same_target_model'):
                        model = self.find_same_target_model
                    else:
                        self._log_message(f"find_same_target_model不存在", source="sync")
                        return
                else:
                    # 默认使用sync视图的组件
                    if not hasattr(self, 'sync_target_tree') or self.sync_target_tree is None:
                        self._log_message(f"sync_target_tree组件不存在", source="sync")
                        return
                    tree = self.sync_target_tree
                    
                    current_model = tree.model()
                    if hasattr(self, 'target_diff_proxy') and current_model == self.target_diff_proxy:
                        model = self.target_diff_proxy
                        source_model = self.sync_target_model
                        use_proxy = True
                    elif hasattr(self, 'sync_target_model'):
                        model = self.sync_target_model
                        use_proxy = False
                    else:
                        self._log_message(f"无法获取有效的文件系统模型", source="sync")
                        return
                
                # 检查tree和model是否存在
                if tree is None or model is None:
                    self._log_message(f"找不到tree或model组件", source="sync")
                    return
                
                # 创建右键菜单
                try:
                    # 不依赖self.window，使用tree作为父组件
                    menu = QMenu(tree)
                except Exception as e:
                    self._log_message(f"创建右键菜单失败: {str(e)}", source="sync")
                    logging.error(f"创建右键菜单失败详情: {traceback.format_exc()}")
                    return
                
                # 获取选中的索引
                try:
                    selection_model = tree.selectionModel()
                    selected_indices = []
                    if selection_model:
                        selected_indices = list(selection_model.selectedRows())
                        
                        # 只有在sync标签页才显示复制到左侧的选项
                        if tab == "sync" and selected_indices:
                            try:
                                # 创建索引副本，避免闭包引用问题
                                indices_copy = selected_indices.copy()
                                copy_to_left_action = QAction("复制到左侧文件夹", tree)
                                # 使用lambda时捕获当前值
                                def on_copy_action_triggered(checked, idx=indices_copy, dir="left", mdl=model):
                                    try:
                                        self._copy_selected_files(idx, dir, mdl)
                                    except Exception as inner_e:
                                        error_msg = f"执行复制操作时出错: {str(inner_e)}"
                                        self._log_message(error_msg, source="sync")
                                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                                        try:
                                            QMessageBox.critical(app.activeWindow(), "错误", error_msg)
                                        except:
                                            pass
                                
                                copy_to_left_action.triggered.connect(on_copy_action_triggered)
                                menu.addAction(copy_to_left_action)
                            except Exception as e:
                                error_msg = f"添加复制菜单项失败: {str(e)}"
                                self._log_message(error_msg, source="sync")
                                logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                except Exception as e:
                    error_msg = f"获取选中索引时出错: {str(e)}"
                    self._log_message(error_msg, source="sync")
                    logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                
                # 获取当前位置的索引
                try:
                    index = tree.indexAt(position)
                    if index.isValid():
                        try:
                            # 如果使用代理模型，需要转换为源模型索引
                            if use_proxy and source_model:
                                source_index = model.mapToSource(index)
                                if not source_index.isValid():
                                    self._log_message("无法转换为源模型索引", source="sync")
                                    # 继续执行，不返回，避免菜单无法显示其他选项
                                else:
                                    file_path = source_model.filePath(source_index)
                            else:
                                # 直接使用原始模型
                                file_path = model.filePath(index)
                            
                            # 检查是否是目录
                            if os.path.isdir(file_path):
                                set_as_target_action = QAction("设为文件夹B", tree)
                                # 使用lambda时捕获当前值
                                def on_set_target_action_triggered(checked, path=file_path, t=tab):
                                    try:
                                        self._set_as_target_folder(path, tab=t)
                                    except Exception as inner_e:
                                        error_msg = f"设置文件夹B时出错: {str(inner_e)}"
                                        self._log_message(error_msg, source="sync")
                                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                                        try:
                                            QMessageBox.critical(app.activeWindow(), "错误", error_msg)
                                        except:
                                            pass
                                
                                set_as_target_action.triggered.connect(on_set_target_action_triggered)
                                menu.addAction(set_as_target_action)
                        except Exception as e:
                            error_msg = f"处理文件路径时出错: {str(e)}"
                            self._log_message(error_msg, source="sync")
                            logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                except Exception as e:
                    error_msg = f"获取索引信息时出错: {str(e)}"
                    self._log_message(error_msg, source="sync")
                    logging.error(f"{error_msg}详情: {traceback.format_exc()}")
                
                # 显示菜单（如果有菜单项）
                if menu.actions():
                    try:
                        menu.exec(tree.viewport().mapToGlobal(position))
                    except Exception as e:
                        error_msg = f"显示右键菜单时出错: {str(e)}"
                        self._log_message(error_msg, source="sync")
                        logging.error(f"{error_msg}详情: {traceback.format_exc()}")
            except Exception as e:
                error_msg = f"设置tree和model时出错: {str(e)}"
                self._log_message(error_msg, source="sync")
                logging.error(f"{error_msg}详情: {traceback.format_exc()}")
        except Exception as e:
            error_msg = f"显示目标文件夹右键菜单时出错: {str(e)}"
            self._log_message(error_msg, source="sync")
            logging.error(f"右键菜单错误详情: {traceback.format_exc()}")
            try:
                if PYQT_AVAILABLE:
                    QMessageBox.critical(getattr(self, 'window', None), "错误", f"右键菜单操作失败: {str(e)}")
            except:
                pass
    
    def _set_as_source_folder(self, folder_path, tab="sync"):
        """将选中的文件夹设为文件夹A"""
        if tab == "sync":
            self.sync_folder_a_edit.setText(folder_path)
            # 更新同步页面源文件夹内容显示
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.sync_source_tree, self.sync_source_model, folder_path)
                # 自动比较：只要两个文件夹都已选择，就立即开始比对
                if self.sync_folder_b_edit.text():
                    self._auto_compare_if_ready(force=True)
                # 同步高度
                self._sync_tree_heights()
        elif tab == "find_same":
            self.find_same_folder_a_edit.setText(folder_path)
            # 更新比对页面源文件夹内容显示
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.find_same_source_tree, self.find_same_source_model, folder_path)
            # 只要两个文件夹都已选择，就立即开始比对（自动比对）
            if self.find_same_folder_b_edit.text():
                self._find_same_files()
        else:
            # 默认行为
            self.sync_folder_a_edit.setText(folder_path)
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.sync_source_tree, self.sync_source_model, folder_path)
        # 根据tab参数决定日志来源
        log_source = "find_same" if tab == "find_same" else "sync"
        self._log_message(f"已设置文件夹A: {folder_path}", source=log_source)
    
    def _set_as_target_folder(self, folder_path, tab=None):
        """将选中的文件夹设为文件夹B"""
        if tab == "sync":
            self.sync_folder_b_edit.setText(folder_path)
            # 更新同步页面目标文件夹内容显示
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.sync_target_tree, self.sync_target_model, folder_path)
                # 自动比较：只要两个文件夹都已选择，就立即开始比对
                if self.sync_folder_a_edit.text():
                    self._auto_compare_if_ready(force=True)
                # 同步高度
                self._sync_tree_heights()
        elif tab == "find_same":
            self.find_same_folder_b_edit.setText(folder_path)
            # 更新比对页面目标文件夹内容显示
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.find_same_target_tree, self.find_same_target_model, folder_path)
            # 只要两个文件夹都已选择，就立即开始比对（自动比对）
            if self.find_same_folder_a_edit.text():
                self._find_same_files()
        else:
            # 默认行为
            self.sync_folder_b_edit.setText(folder_path)
            if QFileSystemModel is not None:
                self._set_root_index_safe(self.sync_target_tree, self.sync_target_model, folder_path)
        # 根据tab参数决定日志来源
        log_source = "find_same" if tab == "find_same" else "sync"
        self._log_message(f"已设置文件夹B: {folder_path}", source=log_source)

    def _on_sync_folder_text_changed(self, which: str):
        """处理同步页面中文件夹路径的手动输入变化"""
        if not (PYQT_AVAILABLE and QFileSystemModel is not None):
            return

        folder_a = self.sync_folder_a_edit.text().strip()
        folder_b = self.sync_folder_b_edit.text().strip()

        if which == "A":
            current_path = folder_a
            model = getattr(self, "sync_source_model", None)
            tree = getattr(self, "sync_source_tree", None)
            other_valid = os.path.isdir(folder_b)
        else:
            current_path = folder_b
            model = getattr(self, "sync_target_model", None)
            tree = getattr(self, "sync_target_tree", None)
            other_valid = os.path.isdir(folder_a)

        # 如果输入框为空，重置为显示"我的电脑"（所有驱动器）
        if model and tree:
            if not current_path:
                from PyQt6.QtCore import QModelIndex
                tree.setRootIndex(QModelIndex())  # 设置为无效索引，显示"我的电脑"
            elif os.path.isdir(current_path):
                self._set_root_index_safe(tree, model, current_path)
                self._sync_tree_heights()

        if os.path.isdir(current_path) and other_valid:
            if which == "B":
                self._auto_compare_if_ready(force=True)
            else:
                self._schedule_auto_compare()
        else:
            self._schedule_auto_compare()

    def _schedule_auto_compare(self):
        """启动防抖定时器，避免频繁触发比对"""
        if hasattr(self, "auto_compare_timer"):
            self.auto_compare_timer.stop()
            self.auto_compare_timer.start()

    def _auto_compare_if_ready(self, force: bool = False):
        """当两个文件夹都可用时自动开始比对"""
        if not (PYQT_AVAILABLE and QFileSystemModel is not None):
            return

        folder_a = self.sync_folder_a_edit.text().strip()
        folder_b = self.sync_folder_b_edit.text().strip()

        if os.path.isdir(folder_a) and os.path.isdir(folder_b):
            if hasattr(self, "auto_compare_timer"):
                self.auto_compare_timer.stop()
            if self.only_show_diff_files.isChecked():
                # 显示差异文件
                self._update_diff_file_display()
            else:
                # 显示所有文件
                self._show_all_sync_files(folder_a, folder_b)
        elif force:
            # 如果强制触发但路径无效，忽略处理
            pass

    def _on_find_same_folder_text_changed(self):
        """处理相同文件比对页面中文件夹路径的手动输入变化"""
        if not (PYQT_AVAILABLE and QFileSystemModel is not None):
            return

        folder_a = self.find_same_folder_a_edit.text().strip()
        folder_b = self.find_same_folder_b_edit.text().strip()

        # 更新文件树视图
        if os.path.isdir(folder_a):
            self._set_root_index_safe(self.find_same_source_tree, self.find_same_source_model, folder_a)
        else:
            # 如果输入框为空，重置为显示"我的电脑"（所有驱动器）
            from PyQt6.QtCore import QModelIndex
            self.find_same_source_tree.setRootIndex(QModelIndex())

        if os.path.isdir(folder_b):
            self._set_root_index_safe(self.find_same_target_tree, self.find_same_target_model, folder_b)
        else:
            # 如果输入框为空，重置为显示"我的电脑"（所有驱动器）
            from PyQt6.QtCore import QModelIndex
            self.find_same_target_tree.setRootIndex(QModelIndex())

        # 启动防抖定时器
        self._schedule_find_same_compare()

    def _schedule_find_same_compare(self):
        """启动相同文件比对防抖定时器，避免频繁触发比对"""
        if hasattr(self, "find_same_timer"):
            self.find_same_timer.stop()
            self.find_same_timer.start()

    def _find_same_files_if_ready(self):
        """当两个文件夹都可用时自动开始相同文件比对"""
        if not (PYQT_AVAILABLE and QFileSystemModel is not None):
            return

        folder_a = self.find_same_folder_a_edit.text().strip()
        folder_b = self.find_same_folder_b_edit.text().strip()

        if os.path.isdir(folder_a) and os.path.isdir(folder_b):
            if hasattr(self, "find_same_timer"):
                self.find_same_timer.stop()
            # 开始相同文件比对
            self._find_same_files_with_no_duplicates()

    def _show_all_sync_files(self, folder_a: str = None, folder_b: str = None):
        """显示同步页面中两个文件夹的全部内容"""
        if not (PYQT_AVAILABLE and QFileSystemModel is not None):
            return

        if hasattr(self, "diff_scan_thread"):
            self.diff_scan_thread.stop()
            self.diff_scan_thread.wait()

        folder_a = folder_a or self.sync_folder_a_edit.text().strip()
        folder_b = folder_b or self.sync_folder_b_edit.text().strip()

        from PyQt6.QtCore import QModelIndex
        self.sync_source_tree.setRootIndex(QModelIndex())
        self.sync_target_tree.setRootIndex(QModelIndex())

        self.sync_source_tree.setModel(self.sync_source_model)
        self.sync_target_tree.setModel(self.sync_target_model)

        if folder_a:
            self.sync_source_tree.setRootIndex(self.sync_source_model.index(folder_a))
        if folder_b:
            self.sync_target_tree.setRootIndex(self.sync_target_model.index(folder_b))
    
    def _update_tree_content(self, tree, directory):
        """更新Tkinter中Treeview的内容（用于Tkinter模式）"""
        # 清空现有内容
        for item in tree.get_children():
            tree.delete(item)
        
        try:
            # 获取目录内容
            items = os.listdir(directory)
            for item in items:
                item_path = os.path.join(directory, item)
                try:
                    # 获取文件信息
                    stat_info = os.stat(item_path)
                    
                    # 判断是否为目录
                    if os.path.isdir(item_path):
                        size = "文件夹"
                        item_type = "文件夹"
                    else:
                        size = f"{stat_info.st_size:,}"  # 格式化文件大小
                        item_type = os.path.splitext(item)[1].lower() or "文件"
                    
                    # 格式化修改时间
                    modified = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    
                    # 添加到Treeview
                    tree.insert("", tk.END, values=(item, size, item_type, modified))
                except Exception as e:
                    # 忽略无法访问的文件
                    pass
        except Exception as e:
            self._log_message(f"读取目录内容失败: {str(e)}")
            
    def _on_only_diff_changed(self):
        """当只显示不同文件的选项改变时调用"""
        if self.only_show_diff_files.isChecked():
            self._auto_compare_if_ready(force=True)
        else:
            self._show_all_sync_files()
                    
    # 差异文件扫描线程类
    class DiffFileScanThread(QThread if PYQT_AVAILABLE else threading.Thread):
        """用于在后台扫描差异文件的线程"""
        if PYQT_AVAILABLE:
            scan_completed = pyqtSignal(dict)  # 发送字典包含两个目录的文件集合
            scan_progress = pyqtSignal(str)  # 发送当前扫描的文件路径
        
        def __init__(self, folder_a, folder_b):
            super().__init__()
            self.folder_a = folder_a
            self.folder_b = folder_b
            self._stop_requested = False
        
        def run(self):
            """运行扫描线程"""
            try:
                # 初始化文件集合
                folder_a_files = set()
                folder_b_files = set()
                
                # 先扫描根目录下的文件和文件夹，这样可以快速显示顶层差异
                if PYQT_AVAILABLE:
                    self.scan_progress.emit(f"开始扫描文件夹: {self.folder_a}")
                
                # 先扫描顶层
                self._scan_directory_level(self.folder_a, folder_a_files, level=1)
                self._scan_directory_level(self.folder_b, folder_b_files, level=1)
                
                # 发送当前结果，这样用户可以看到初步的差异
                if PYQT_AVAILABLE:
                    self.scan_completed.emit({
                        'folder_a': folder_a_files,
                        'folder_b': folder_b_files,
                        'completed': False
                    })
                
                # 如果用户没有停止，继续扫描更深层次
                if not self._stop_requested:
                    if PYQT_AVAILABLE:
                        self.scan_progress.emit(f"扫描更多文件...")
                    # 扫描所有层级
                    self._scan_directory_level(self.folder_a, folder_a_files, level=None)
                    self._scan_directory_level(self.folder_b, folder_b_files, level=None)
                
                # 扫描完成
                if PYQT_AVAILABLE:
                    self.scan_completed.emit({
                        'folder_a': folder_a_files,
                        'folder_b': folder_b_files,
                        'completed': True
                    })
                    self.scan_progress.emit("扫描完成")
                    
            except Exception as e:
                if PYQT_AVAILABLE:
                    self.scan_progress.emit(f"扫描出错: {str(e)}")
        
        def _scan_directory_level(self, directory, file_set, level=None):
            """扫描指定层级的目录
            level: None表示扫描所有层级，1表示只扫描顶层，2表示扫描两层，以此类推
            """
            base_depth = directory.count(os.sep)
            total_files_scanned = 0
            total_dirs_scanned = 0
            
            for root, dirs, files in os.walk(directory):
                # 检查是否应该停止
                if self._stop_requested:
                    if PYQT_AVAILABLE:
                        self.scan_progress.emit(f"扫描已停止，已扫描{total_files_scanned}个文件，{total_dirs_scanned}个目录")
                    break
                
                # 检查目录深度
                current_depth = root.count(os.sep)
                if level is not None and (current_depth - base_depth) >= level:
                    # 跳过更深的目录
                    dirs[:] = []  # 清空dirs以阻止进一步递归
                    continue
                
                # 发送当前扫描目录的信息
                if PYQT_AVAILABLE and files:
                    self.scan_progress.emit(f"扫描目录: {root} (发现{len(files)}个文件)")
                
                # 添加文件
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, directory)
                    file_set.add(rel_path)
                    total_files_scanned += 1
                    # 每100个文件更新一次进度
                    if PYQT_AVAILABLE and total_files_scanned % 100 == 0:
                        self.scan_progress.emit(f"已扫描{total_files_scanned}个文件，{total_dirs_scanned}个目录")
                
                # 添加目录
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    rel_path = os.path.relpath(dir_path, directory)
                    file_set.add(rel_path)
                    total_dirs_scanned += 1
            
            # 扫描完成后发送总结信息
            if PYQT_AVAILABLE and not self._stop_requested:
                self.scan_progress.emit(f"完成扫描{directory}，共扫描{total_files_scanned}个文件，{total_dirs_scanned}个目录")
        
        def stop(self):
            """停止扫描"""
            self._stop_requested = True
    
    # 差异文件过滤器代理模型
    if PYQT_AVAILABLE and QSortFilterProxyModel is not None:
        class DiffFileFilterProxyModel(QSortFilterProxyModel):
            def __init__(self, source_dir, target_dir, parent=None):
                super().__init__(parent)
                self.source_dir = source_dir
                self.target_dir = target_dir
                self.source_files = set()
                self.target_files = set()
                self.filter_active = False  # 控制过滤是否激活
            
            def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
                """重写表头数据以显示中文列名"""
                if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
                    if section == 0:
                        return "名称"
                    elif section == 1:
                        return "大小"
                    elif section == 2:
                        return "类型"
                    elif section == 3:
                        return "修改日期"
                return super().headerData(section, orientation, role)
            
            def update_file_sets(self, source_files, target_files):
                """更新文件集合"""
                self.source_files = source_files
                self.target_files = target_files
                self.filter_active = True
                self.invalidateFilter()  # 重新应用过滤
            
            def filterAcceptsRow(self, source_row, source_parent):
                # 如果过滤未激活，显示所有文件
                if not self.filter_active:
                    return True
                
                source_model = self.sourceModel()
                # 检查源模型是否有效
                if source_model is None:
                    return True
                
                # 获取索引并检查有效性
                index = source_model.index(source_row, 0, source_parent)
                if not index.isValid():
                    return True
                
                # 安全获取文件路径
                try:
                    file_path = source_model.filePath(index)
                except Exception:
                    return True
                
                # 检查文件路径是否有效
                if not file_path:
                    return True
                
                # 确保路径分隔符统一为正斜杠
                file_path = file_path.replace('\\', '/')
                source_dir = self.source_dir.replace('\\', '/') if self.source_dir else ''
                target_dir = self.target_dir.replace('\\', '/') if self.target_dir else ''
                
                # 获取相对路径并过滤
                if source_dir and file_path.startswith(source_dir):
                    try:
                        # 计算相对路径，处理顶层目录的特殊情况
                        if file_path == source_dir:
                            # 对于源目录本身，我们应该始终显示
                            return True
                        
                        # 计算相对路径，确保正确处理路径格式
                        rel_path = os.path.relpath(file_path, self.source_dir).replace('\\', '/')
                        
                        # 标准化目标文件集合的路径分隔符
                        normalized_target_files = {f.replace('\\', '/') for f in self.target_files}
                        
                        # 对于目录，我们需要检查它是否包含任何差异文件
                        # 如果是目录，只要它包含至少一个差异文件，就应该显示
                        if source_model.isDir(index):
                            # 检查目录路径是否在目标文件集合中不存在
                            # 或者检查目录下是否有差异文件
                            dir_rel_path = rel_path + '/' if not rel_path.endswith('/') else rel_path
                            has_diff_in_dir = not any(t_file.startswith(dir_rel_path) for t_file in normalized_target_files)
                            return has_diff_in_dir or rel_path not in normalized_target_files
                        else:
                            # 对于文件，直接检查是否在目标文件集合中不存在
                            return rel_path not in normalized_target_files
                    except Exception as e:
                        # 出错时默认显示该文件，避免错误过滤
                        # 记录异常但不阻止显示
                        return True
                elif target_dir and file_path.startswith(target_dir):
                    try:
                        # 计算相对路径，处理顶层目录的特殊情况
                        if file_path == target_dir:
                            # 对于目标目录本身，我们应该始终显示
                            return True
                        
                        # 计算相对路径，确保正确处理路径格式
                        rel_path = os.path.relpath(file_path, self.target_dir).replace('\\', '/')
                        
                        # 标准化源文件集合的路径分隔符
                        normalized_source_files = {f.replace('\\', '/') for f in self.source_files}
                        
                        # 对于目录，我们需要检查它是否包含任何差异文件
                        # 如果是目录，只要它包含至少一个差异文件，就应该显示
                        if source_model.isDir(index):
                            # 检查目录路径是否在源文件集合中不存在
                            # 或者检查目录下是否有差异文件
                            dir_rel_path = rel_path + '/' if not rel_path.endswith('/') else rel_path
                            has_diff_in_dir = not any(s_file.startswith(dir_rel_path) for s_file in normalized_source_files)
                            return has_diff_in_dir or rel_path not in normalized_source_files
                        else:
                            # 对于文件，直接检查是否在源文件集合中不存在
                            return rel_path not in normalized_source_files
                    except Exception as e:
                        # 出错时默认显示该文件，避免错误过滤
                        # 记录异常但不阻止显示
                        return True
                
                # 默认返回True，确保当文件路径不在已知目录下时仍能显示
                # 这避免了因为路径匹配问题导致文件不显示的情况
                return True
    
    def _update_diff_file_display(self):
        """更新文件树显示，只显示不同的文件和文件夹"""
        if not PYQT_AVAILABLE or QFileSystemModel is None:
            return
        
        folder_a = self.sync_folder_a_edit.text()
        folder_b = self.sync_folder_b_edit.text()
        
        if not folder_a or not folder_b:
            return

        # 如果未勾选“只显示不同的文件/文件夹”，则直接显示全部内容
        if hasattr(self, "only_show_diff_files") and not self.only_show_diff_files.isChecked():
            self._show_all_sync_files(folder_a, folder_b)
            return
            
        try:
            # 先显示所有文件，然后逐步过滤
            if PYQT_AVAILABLE:
                try:
                    from PyQt6.QtCore import QSortFilterProxyModel
                except ImportError:
                    # 如果导入失败，直接返回
                    return
            else:
                # 如果PyQt不可用，直接返回
                return
            
            # 记录更新操作的开始
            self._log_message(f"准备更新差异文件显示: 文件夹A={folder_a}, 文件夹B={folder_b}", source="sync")
            
            # 强制刷新文件系统模型，确保获取最新文件信息
            if hasattr(self, 'sync_source_model') and hasattr(self, 'sync_folder_a_edit'):
                folder_a = self.sync_folder_a_edit.text()
                if folder_a:
                    # 重置根路径以刷新模型
                    root_index = self.sync_source_model.index(folder_a)
                    if root_index.isValid():
                        self.sync_source_model.setRootPath(folder_a)
            if hasattr(self, 'sync_target_model') and hasattr(self, 'sync_folder_b_edit'):
                folder_b = self.sync_folder_b_edit.text()
                if folder_b:
                    # 重置根路径以刷新模型
                    root_index = self.sync_target_model.index(folder_b)
                    if root_index.isValid():
                        self.sync_target_model.setRootPath(folder_b)
            
            # 停止并清理之前可能在运行的扫描线程
            if hasattr(self, 'diff_scan_thread'):
                self._log_message("停止之前的扫描线程...", source="sync")
                self.diff_scan_thread.stop()
                # 设置一个较短的超时时间，避免线程长时间阻塞
                if not self.diff_scan_thread.wait(2000):  # 等待2秒
                    self._log_message("扫描线程等待超时，继续执行", source="sync")
                # 解除信号连接，避免重复处理
                if PYQT_AVAILABLE:
                    try:
                        self.diff_scan_thread.scan_completed.disconnect()
                        self.diff_scan_thread.scan_progress.disconnect()
                    except:
                        pass
                # 清空线程引用
                del self.diff_scan_thread
            
            # 清除现有的根索引，避免索引和模型不匹配
            from PyQt6.QtCore import QModelIndex
            self.sync_source_tree.setRootIndex(QModelIndex())
            self.sync_target_tree.setRootIndex(QModelIndex())
            
            # 重置代理模型，确保每次都使用新的实例
            # 创建过滤器模型
            self.source_diff_proxy = self.DiffFileFilterProxyModel(folder_a, folder_b)
            self.target_diff_proxy = self.DiffFileFilterProxyModel(folder_b, folder_a)
            
            # 禁用过滤功能，先显示所有文件
            self.source_diff_proxy.filter_active = False
            self.target_diff_proxy.filter_active = False
            
            # 设置源模型
            self.source_diff_proxy.setSourceModel(self.sync_source_model)
            self.target_diff_proxy.setSourceModel(self.sync_target_model)
            
            # 设置原始模型的根索引
            source_index = self.sync_source_model.index(folder_a)
            target_index = self.sync_target_model.index(folder_b)
            
            # 直接使用代理模型并设置正确的根索引
            self.sync_source_tree.setModel(self.source_diff_proxy)
            self.sync_target_tree.setModel(self.target_diff_proxy)
            
            # 将原始模型的根索引映射到代理模型
            if source_index.isValid():
                proxy_source_index = self.source_diff_proxy.mapFromSource(source_index)
                if proxy_source_index.isValid():
                    self.sync_source_tree.setRootIndex(proxy_source_index)
            if target_index.isValid():
                proxy_target_index = self.target_diff_proxy.mapFromSource(target_index)
                if proxy_target_index.isValid():
                    self.sync_target_tree.setRootIndex(proxy_target_index)
            
            # 强制刷新视图
            self.sync_source_tree.viewport().update()
            self.sync_target_tree.viewport().update()
            
            # 创建并启动扫描线程
            self._log_message("创建新的扫描线程...", source="sync")
            self.diff_scan_thread = self.DiffFileScanThread(folder_a, folder_b)
            
            # 连接信号
            if PYQT_AVAILABLE:
                self.diff_scan_thread.scan_completed.connect(self._on_diff_scan_update)
                self.diff_scan_thread.scan_progress.connect(lambda msg: self._log_message(msg, source="sync"))
            
            # 记录开始比对的日志
            self._log_message(f"开始比对文件夹: {folder_a} 和 {folder_b}", source="sync")
            
            # 启动线程
            self.diff_scan_thread.start()
            
        except Exception as e:
            self._log_message(f"更新差异文件显示时出错: {str(e)}", source="sync")
            # 出错时显示所有文件，避免界面空白
            self._show_all_sync_files(folder_a, folder_b)
            # 出错时恢复原始显示
            try:
                # 停止扫描线程
                if hasattr(self, 'diff_scan_thread'):
                    self.diff_scan_thread.stop()
                    self.diff_scan_thread.wait()
                
                # 重置模型和索引
                self.sync_source_tree.setModel(self.sync_source_model)
                self.sync_target_tree.setModel(self.sync_target_model)
                if folder_a:
                    self.sync_source_tree.setRootIndex(self.sync_source_model.index(folder_a))
                if folder_b:
                    self.sync_target_tree.setRootIndex(self.sync_target_model.index(folder_b))
                
                # 清除代理模型引用
                if hasattr(self, 'source_diff_proxy'):
                    delattr(self, 'source_diff_proxy')
                if hasattr(self, 'target_diff_proxy'):
                    delattr(self, 'target_diff_proxy')
            except Exception as inner_e:
                self._log_message(f"恢复显示时出错: {str(inner_e)}", source="sync")
    
    def _sync_tree_heights(self):
        """确保所有控件高度保持一致，包括文件树和浏览控件"""
        if PYQT_AVAILABLE:
            try:
                # 1. 首先对所有浏览控件应用固定高度，确保完全一致
                # 确保浏览输入框高度一致
                if hasattr(self, 'sync_folder_a_edit'):
                    self.sync_folder_a_edit.setMinimumHeight(35)
                    self.sync_folder_a_edit.setMaximumHeight(35)
                    self.sync_folder_a_edit.setFixedHeight(35)
                if hasattr(self, 'sync_folder_b_edit'):
                    self.sync_folder_b_edit.setMinimumHeight(35)
                    self.sync_folder_b_edit.setMaximumHeight(35)
                    self.sync_folder_b_edit.setFixedHeight(35)
                
                # 确保浏览按钮高度一致
                if hasattr(self, 'sync_browse_a_btn'):
                    self.sync_browse_a_btn.setMinimumHeight(35)
                    self.sync_browse_a_btn.setMaximumHeight(35)
                    self.sync_browse_a_btn.setFixedHeight(35)
                    if PYQT_AVAILABLE:
                        self.sync_browse_a_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
                if hasattr(self, 'sync_browse_b_btn'):
                    self.sync_browse_b_btn.setMinimumHeight(35)
                    self.sync_browse_b_btn.setMaximumHeight(35)
                    self.sync_browse_b_btn.setFixedHeight(35)
                    if PYQT_AVAILABLE:
                        self.sync_browse_b_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
                
                # 2. 同步文件树高度
                if hasattr(self, 'sync_source_tree') and hasattr(self, 'sync_target_tree'):
                    # 获取A的当前高度
                    a_height = self.sync_source_tree.height()
                    a_width = self.sync_source_tree.width()
                    
                    # 先重置最小和最大高度限制，允许布局系统正常工作
                    self.sync_target_tree.setMinimumHeight(0)
                    self.sync_target_tree.setMaximumHeight(16777215)  # Qt中的最大高度值
                    
                    # 同时应用setFixedHeight和resize确保高度完全一致
                    self.sync_target_tree.setFixedHeight(a_height)
                    self.sync_target_tree.resize(a_width, a_height)
                
                # 3. 强制刷新所有控件和布局
                # 收集所有需要刷新的控件
                all_widgets = []
                # 浏览控件
                for widget_name in ['sync_folder_a_edit', 'sync_folder_b_edit', 
                                   'sync_browse_a_btn', 'sync_browse_b_btn',
                                   'sync_source_tree', 'sync_target_tree']:
                    if hasattr(self, widget_name):
                        widget = getattr(self, widget_name)
                        all_widgets.append(widget)
                        # 先单独刷新每个控件
                        widget.ensurePolished()
                        widget.updateGeometry()
                        widget.update()
                
                # 4. 递归刷新所有父布局
                processed_parents = set()
                for widget in all_widgets:
                    parent = widget.parent()
                    while parent and parent not in processed_parents:
                        processed_parents.add(parent)
                        parent.updateGeometry()
                        parent.update()
                        # 更强制的刷新方法
                        if hasattr(parent, 'repolish'):
                            parent.repolish()
                        if hasattr(parent, 'layout') and parent.layout():
                            parent.layout().update()
                            parent.layout().activate()
                        parent = parent.parent()
                
                # 5. 使用定时器确保布局完全更新
                def final_refresh():
                    # 再次处理事件和刷新
                    # 在PyQt6中使用Qt命名空间或直接使用默认参数
                    QApplication.processEvents()
                    # 再次刷新所有相关控件
                    for widget in all_widgets:
                        widget.update()
                
                # 使用单次定时器确保在事件循环空闲时执行最终刷新
                QTimer.singleShot(10, final_refresh)
                
                # 立即处理所有事件
                QApplication.processEvents()
                
            except Exception as e:
                # 记录异常而不是静默处理
                self._log_message(f"同步控件高度时出错: {str(e)}", source="sync")
    
    def _on_diff_scan_update(self, result):
        """当差异文件扫描更新时调用"""
        try:
            # 记录接收到扫描结果
            self._log_message(f"收到扫描结果: 文件夹A包含{len(result.get('folder_a', []))}个文件/目录, 文件夹B包含{len(result.get('folder_b', []))}个文件/目录", source="sync")
            
            # 验证扫描结果的有效性
            if not isinstance(result, dict):
                self._log_message("错误: 扫描结果不是有效的字典类型", source="sync")
                return
                
            # 确保result字典包含必要的键
            if 'folder_a' not in result or 'folder_b' not in result:
                self._log_message(f"错误: 扫描结果格式错误，缺少必要的文件夹数据键", source="sync")
                return
            
            # 安全获取文件集合并转换为集合类型
            folder_a_files = set(result.get('folder_a', []))
            folder_b_files = set(result.get('folder_b', []))
            
            # 验证扫描结果是否为空
            if not folder_a_files and not folder_b_files:
                self._log_message("警告: 扫描结果为空，请检查文件夹路径是否正确且可访问", source="sync")
            
            # 更新文件过滤器的文件集合
            if hasattr(self, 'source_diff_proxy') and hasattr(self, 'target_diff_proxy'):
                # 确保过滤功能已启用
                self.source_diff_proxy.filter_active = True
                self.target_diff_proxy.filter_active = True
                
                # 使用update_file_sets方法确保正确更新和过滤
                self.source_diff_proxy.update_file_sets(folder_a_files, folder_b_files)
                self.target_diff_proxy.update_file_sets(folder_b_files, folder_a_files)
                
                # 刷新过滤器
                self.source_diff_proxy.invalidateFilter()
                self.target_diff_proxy.invalidateFilter()
                
                # 重新设置根索引
                folder_a = self.sync_folder_a_edit.text()
                folder_b = self.sync_folder_b_edit.text()
                
                # 确保左右两侧资源管理器使用相同的根索引处理逻辑
                if folder_a and hasattr(self, 'sync_source_model'):
                    try:
                        source_index = self.sync_source_model.index(folder_a)
                        if source_index.isValid():
                            # 安全地转换为代理模型的索引
                            proxy_index = self.source_diff_proxy.mapFromSource(source_index)
                            if proxy_index.isValid():
                                self.sync_source_tree.setRootIndex(proxy_index)
                    except Exception as idx_e:
                        self._log_message(f"设置源文件夹索引时出错: {str(idx_e)}", source="sync")
                
                if folder_b and hasattr(self, 'sync_target_model'):
                    try:
                        target_index = self.sync_target_model.index(folder_b)
                        if target_index.isValid():
                            # 安全地转换为代理模型的索引
                            proxy_index = self.target_diff_proxy.mapFromSource(target_index)
                            if proxy_index.isValid():
                                self.sync_target_tree.setRootIndex(proxy_index)
                    except Exception as idx_e:
                        self._log_message(f"设置目标文件夹索引时出错: {str(idx_e)}", source="sync")
                
                # 计算并记录差异文件数量信息
                common_files = folder_a_files & folder_b_files
                diff_count_a = len(folder_a_files) - len(common_files)
                diff_count_b = len(folder_b_files) - len(common_files)
                
                # 计算差异文件列表
                diff_a_b = sorted([f for f in folder_a_files if f not in folder_b_files])
                diff_b_a = sorted([f for f in folder_b_files if f not in folder_a_files])
                
                # 记录差异信息
                self._log_message(f"发现差异文件: A独有 {diff_count_a} 个, B独有 {diff_count_b} 个", source="sync")
                
                # 如果扫描完成，显示最终消息并确保视图更新
                if result.get('completed', False):
                    self._log_message(f"差异文件扫描完成，A中有{len(folder_a_files)}个文件/目录，B中有{len(folder_b_files)}个文件/目录", source="sync")
                    self._log_message(f"A中独有的文件/目录数量: {len(diff_a_b)}，B中独有的文件/目录数量: {len(diff_b_a)}", source="sync")
                    self._log_message(f"共有{len(common_files)}个文件/目录在A和B中都存在", source="sync")
                    
                    # 如果有差异文件，记录部分示例（最多显示前5个）
                    if diff_count_a > 0:
                        sample_diff_a = ", ".join(diff_a_b[:5]) + ("..." if len(diff_a_b) > 5 else "")
                        self._log_message(f"A独有文件示例: {sample_diff_a}", source="sync")
                    if diff_count_b > 0:
                        sample_diff_b = ", ".join(diff_b_a[:5]) + ("..." if len(diff_b_a) > 5 else "")
                        self._log_message(f"B独有文件示例: {sample_diff_b}", source="sync")
                    
                    # 展开树视图以显示差异文件
                    self.sync_source_tree.expandAll()
                    self.sync_target_tree.expandAll()
                    
                    # 同步高度
                    self._sync_tree_heights()
                    
                    # 强制刷新视图以确保正确显示
                    self.sync_source_tree.viewport().update()
                    self.sync_target_tree.viewport().update()
                    
                    # 触发UI事件循环处理
                    from PyQt6.QtWidgets import QApplication
                    QApplication.processEvents()
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            self._log_message(f"更新差异文件显示时出错: {str(e)}，详细错误: {error_trace}", source="sync")
            # 出错时重置过滤状态，确保至少能显示所有文件
            if hasattr(self, 'source_diff_proxy'):
                try:
                    self.source_diff_proxy.filter_active = False
                except:
                    pass
            if hasattr(self, 'target_diff_proxy'):
                try:
                    self.target_diff_proxy.filter_active = False
                except:
                    pass
                
    def _copy_selected_files(self, selected_indices, direction, model):
        """复制选中的文件到目标文件夹
        
        Args:
            selected_indices: 选中的索引列表
            direction: 复制方向，"left" 或 "right"
            model: 文件系统模型（可能是代理模型）
        """
        import traceback  # 在方法开始就导入，避免在异常处理块中导入
        try:
            # 基本安全检查
            app = QApplication.instance()
            if not PYQT_AVAILABLE or not app:
                self._log_message("复制文件失败: PyQt不可用或应用实例不存在", source="sync")
                # 尝试通过QApplication显示消息
                try:
                    if app:
                        QMessageBox.warning(app.activeWindow(), "警告", "无法执行复制操作: 应用环境不正确")
                except Exception as msg_e:
                    self._log_message(f"无法显示警告消息: {str(msg_e)}", source="sync")
                return
            
            # 严格检查参数有效性
            if selected_indices is None or not isinstance(selected_indices, (list, tuple)):
                error_msg = "无效的文件索引列表: 不是有效的列表类型"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查索引列表是否为空
            if len(selected_indices) == 0:
                error_msg = "没有选中的文件"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.information(app.activeWindow(), "提示", error_msg)
                except:
                    pass
                return
            
            # 验证每个索引的有效性
            valid_indices = []
            for idx in selected_indices:
                try:
                    if hasattr(idx, 'isValid') and callable(idx.isValid) and idx.isValid():
                        valid_indices.append(idx)
                except Exception as idx_e:
                    self._log_message(f"发现无效索引: {str(idx_e)}", source="sync")
                    continue
            
            if len(valid_indices) == 0:
                error_msg = "所有选中的文件索引均无效"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查direction参数
            if direction is None or direction not in ("left", "right"):
                error_msg = "无效的复制方向参数"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查model参数
            if model is None:
                error_msg = "无效的文件系统模型"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查是否是代理模型，如果是，获取源模型
            source_model = None
            use_proxy = False
            try:
                if hasattr(model, 'sourceModel') and callable(model.sourceModel):
                    # 这是一个代理模型
                    source_model = model.sourceModel()
                    use_proxy = True
                    # 验证源模型是否有效
                    if source_model is None:
                        self._log_message("代理模型的源模型为None", source="sync")
                        use_proxy = False
                else:
                    # 直接使用原始模型
                    source_model = model
                    use_proxy = False
            except Exception as model_e:
                self._log_message(f"获取模型信息时出错: {str(model_e)}", source="sync")
                use_proxy = False
                source_model = model
            
            # 获取源文件夹和目标文件夹，添加更严格的检查
            source_dir = None
            target_dir = None
            tree_to_update = None
            target_model = None
            
            try:
                if direction == "right":
                    # 安全获取UI组件
                    if not hasattr(self, 'sync_folder_a_edit') or self.sync_folder_a_edit is None:
                        error_msg = "UI组件未初始化: 源文件夹编辑控件不存在"
                        self._log_message(error_msg, source="sync")
                        try:
                            QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                        except:
                            pass
                        return
                    if not hasattr(self, 'sync_folder_b_edit') or self.sync_folder_b_edit is None:
                        error_msg = "UI组件未初始化: 目标文件夹编辑控件不存在"
                        self._log_message(error_msg, source="sync")
                        try:
                            QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                        except:
                            pass
                        return
                    
                    # 安全获取文本属性
                    if hasattr(self.sync_folder_a_edit, 'text') and callable(self.sync_folder_a_edit.text):
                        source_dir = self.sync_folder_a_edit.text()
                    else:
                        source_dir = ""
                    if hasattr(self.sync_folder_b_edit, 'text') and callable(self.sync_folder_b_edit.text):
                        target_dir = self.sync_folder_b_edit.text()
                    else:
                        target_dir = ""
                    
                    tree_to_update = getattr(self, 'sync_target_tree', None)
                    target_model = getattr(self, 'sync_target_model', None)
                else:  # direction == "left"
                    # 安全获取UI组件
                    if not hasattr(self, 'sync_folder_b_edit') or self.sync_folder_b_edit is None:
                        error_msg = "UI组件未初始化: 源文件夹编辑控件不存在"
                        self._log_message(error_msg, source="sync")
                        try:
                            QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                        except:
                            pass
                        return
                    if not hasattr(self, 'sync_folder_a_edit') or self.sync_folder_a_edit is None:
                        error_msg = "UI组件未初始化: 目标文件夹编辑控件不存在"
                        self._log_message(error_msg, source="sync")
                        try:
                            QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                        except:
                            pass
                        return
                    
                    # 安全获取文本属性
                    if hasattr(self.sync_folder_b_edit, 'text') and callable(self.sync_folder_b_edit.text):
                        source_dir = self.sync_folder_b_edit.text()
                    else:
                        source_dir = ""
                    if hasattr(self.sync_folder_a_edit, 'text') and callable(self.sync_folder_a_edit.text):
                        target_dir = self.sync_folder_a_edit.text()
                    else:
                        target_dir = ""
                    
                    tree_to_update = getattr(self, 'sync_source_tree', None)
                    target_model = getattr(self, 'sync_source_model', None)
            except Exception as ui_e:
                error_msg = f"获取UI组件时出错: {str(ui_e)}"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查文件夹路径有效性
            if not source_dir or not target_dir or not isinstance(source_dir, str) or not isinstance(target_dir, str):
                error_msg = "请先选择源文件夹和目标文件夹"
                self._log_message(f"复制文件失败: {error_msg}", source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 检查文件夹是否存在
            try:
                if not os.path.isdir(source_dir) or not os.path.isdir(target_dir):
                    error_msg = "源文件夹或目标文件夹不存在或无效"
                    self._log_message(f"复制文件失败: {error_msg}", source="sync")
                    try:
                        QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                    except:
                        pass
                    return
            except Exception as path_e:
                error_msg = f"检查文件夹路径时出错: {str(path_e)}"
                self._log_message(error_msg, source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", error_msg)
                except:
                    pass
                return
            
            # 创建选中索引的副本，避免在多线程中访问原始索引列表
            selected_indices_copy = list(valid_indices)
            
            # 使用新的线程类来复制文件
            if PYQT_AVAILABLE:
                try:
                    # 验证CopyFilesThread类的存在性
                    if 'CopyFilesThread' not in globals() and 'CopyFilesThread' not in locals():
                        raise Exception("CopyFilesThread类未定义")
                    
                    # 创建线程实例，确保参数正确
                    self.copy_thread = CopyFilesThread(
                        self, selected_indices_copy, direction, model, 
                        source_model, use_proxy, source_dir, target_dir
                    )
                    
                    # 连接信号，添加异常处理
                    try:
                        if hasattr(self.copy_thread, 'copy_finished') and hasattr(self, '_on_copy_finished'):
                            self.copy_thread.copy_finished.connect(self._on_copy_finished)
                        if hasattr(self.copy_thread, 'refresh_needed') and hasattr(self, '_on_refresh_needed'):
                            self.copy_thread.refresh_needed.connect(self._on_refresh_needed)
                    except Exception as signal_e:
                        self._log_message(f"连接信号时出错: {str(signal_e)}", source="sync")
                    
                    # 启动线程
                    try:
                        self.copy_thread.start()
                        self._log_message(f"开始复制文件: 从{source_dir}到{target_dir}", source="sync")
                    except Exception as start_e:
                        error_msg = f"启动复制线程时出错: {str(start_e)}"
                        self._log_message(error_msg, source="sync")
                        self._log_message(f"线程启动错误详情: {traceback.format_exc()}", source="sync")
                        try:
                            QMessageBox.critical(app.activeWindow(), "错误", f"启动复制操作失败: {str(start_e)}")
                        except:
                            pass
                except Exception as thread_error:
                    error_msg = f"创建或启动复制线程失败: {str(thread_error)}"
                    self._log_message(error_msg, source="sync")
                    self._log_message(f"线程创建错误详情: {traceback.format_exc()}", source="sync")
                    try:
                        QMessageBox.critical(app.activeWindow(), "错误", f"启动复制操作失败: {str(thread_error)}")
                    except:
                        pass
            else:
                # Tkinter模式的处理（略）
                self._log_message("复制文件失败: 不支持的UI模式", source="sync")
                try:
                    QMessageBox.warning(app.activeWindow(), "警告", "无法执行复制操作: 不支持的UI模式")
                except:
                    pass
            
        except Exception as e:
            error_msg = f"复制文件时发生未知错误: {str(e)}"
            self._log_message(error_msg, source="sync")
            self._log_message(f"错误详情: {traceback.format_exc()}", source="sync")
            # 尝试通过多种方式显示错误信息
            try:
                # 尝试使用QApplication的活动窗口
                QMessageBox.critical(app.activeWindow(), "错误", f"复制文件时出错: {str(e)}")
            except:
                try:
                    # 尝试创建一个独立的消息框
                    msg_box = QMessageBox()
                    msg_box.setWindowTitle("错误")
                    msg_box.setText(f"复制文件时出错: {str(e)}")
                    msg_box.setIcon(QMessageBox.Icon.Critical)
                    msg_box.exec()
                except:
                    # 最后的努力，至少记录到日志
                    self._log_message("无法显示错误消息对话框", source="sync")
    
    def _on_copy_finished(self, copied_count, failed_count):
        """复制完成后的回调（在主线程中）"""
        try:
            self._log_message(f"复制操作完成，正在准备刷新...", source="sync")
            
            # 显示复制结果
            if PYQT_AVAILABLE:
                try:
                    total_count = copied_count + failed_count
                    if failed_count > 0:
                        msg = f"复制完成: 共 {total_count} 个文件，成功 {copied_count} 个，失败 {failed_count} 个"
                        QMessageBox.warning(getattr(self, 'window', None), "复制完成", msg)
                    else:
                        msg = f"复制成功: 共 {copied_count} 个文件"
                        QMessageBox.information(getattr(self, 'window', None), "复制成功", msg)
                except Exception as msg_e:
                    self._log_message(f"显示复制结果消息时出错: {str(msg_e)}", source="sync")
        except Exception as e:
            self._log_message(f"处理复制完成事件时出错: {str(e)}", source="sync")

    def _get_explorer_selected_paths(self):
        paths = []
        try:
            import win32com.client
            shell = win32com.client.Dispatch("Shell.Application")
            for window in shell.Windows():
                try:
                    doc = getattr(window, 'Document', None)
                    if doc is None:
                        continue
                    sel = doc.SelectedItems()
                    if not sel:
                        continue
                    for item in sel:
                        try:
                            p = getattr(item, 'Path', None)
                            if p:
                                paths.append(p)
                        except:
                            pass
                except:
                    pass
        except Exception:
            pass
        return paths

    def _init_with_explorer_selection(self):
        if not PYQT_AVAILABLE or QFileSystemModel is None:
            return
        try:
            selected = self._get_explorer_selected_paths()
            base = None
            for p in selected:
                if isinstance(p, str) and p:
                    if os.path.isdir(p):
                        base = p
                        break
                    if os.path.isfile(p):
                        base = os.path.dirname(p)
                        break
            if not base:
                try:
                    base = os.getcwd()
                except Exception:
                    base = None
            if base and os.path.isdir(base):
                self.sync_folder_a_edit.setText(base)
                self.sync_folder_b_edit.setText(base)
                try:
                    self._set_root_index_safe(self.sync_source_tree, self.sync_source_model, base)
                    self._set_root_index_safe(self.sync_target_tree, self.sync_target_model, base)
                except Exception:
                    pass
                self._sync_tree_heights()
        except Exception:
            pass
    
    def _on_refresh_needed(self):
        """处理刷新需求（在主线程中）"""
        try:
            if not PYQT_AVAILABLE:
                return
            
            # 获取当前的源文件夹和目标文件夹
            try:
                folder_a = self.sync_folder_a_edit.text()
                folder_b = self.sync_folder_b_edit.text()
                
                if not folder_a or not folder_b:
                    self._log_message("无法刷新: 文件夹路径为空", source="sync")
                    return
            except Exception as folder_e:
                self._log_message(f"获取文件夹路径时出错: {str(folder_e)}", source="sync")
                return
            
            self._log_message("开始自动刷新差异显示...", source="sync")
            
            # 重新扫描并更新差异文件显示
            # 这会自动隐藏已经一致的文件和文件夹
            try:
                self._update_diff_file_display()
                self._log_message("差异显示刷新完成，已自动隐藏一致文件", source="sync")
            except Exception as refresh_e:
                self._log_message(f"刷新差异显示时出错: {str(refresh_e)}", source="sync")
                # 尝试基本的刷新操作
                try:
                    self._refresh_sync_trees()
                    self._log_message("执行了基本刷新操作", source="sync")
                except Exception as basic_refresh_e:
                    self._log_message(f"基本刷新操作也失败: {str(basic_refresh_e)}", source="sync")
            
        except Exception as e:
            self._log_message(f"处理刷新需求时出错: {str(e)}", source="sync")

    def _refresh_sync_trees(self):
        """基础刷新：恢复原始模型并重置根索引"""
        if not PYQT_AVAILABLE or QFileSystemModel is None:
            return
        try:
            from PyQt6.QtCore import QModelIndex
            folder_a = self.sync_folder_a_edit.text() if hasattr(self, 'sync_folder_a_edit') else ''
            folder_b = self.sync_folder_b_edit.text() if hasattr(self, 'sync_folder_b_edit') else ''
            if hasattr(self, 'sync_source_tree') and hasattr(self, 'sync_source_model'):
                self.sync_source_tree.setModel(self.sync_source_model)
                self.sync_source_tree.setRootIndex(QModelIndex())
                if folder_a:
                    self.sync_source_tree.setRootIndex(self.sync_source_model.index(folder_a))
            if hasattr(self, 'sync_target_tree') and hasattr(self, 'sync_target_model'):
                self.sync_target_tree.setModel(self.sync_target_model)
                self.sync_target_tree.setRootIndex(QModelIndex())
                if folder_b:
                    self.sync_target_tree.setRootIndex(self.sync_target_model.index(folder_b))
            self._sync_tree_heights()
        except Exception:
            pass

    def _set_root_index_safe(self, tree, source_model, path):
        if not PYQT_AVAILABLE or QFileSystemModel is None:
            return
        try:
            idx = source_model.index(path)
            if not idx.isValid():
                return
            current_model = tree.model()
            if hasattr(current_model, 'mapFromSource') and callable(current_model.mapFromSource):
                proxy_idx = current_model.mapFromSource(idx)
                if proxy_idx.isValid():
                    tree.setRootIndex(proxy_idx)
                else:
                    tree.setModel(source_model)
                    tree.setRootIndex(idx)
            else:
                tree.setRootIndex(idx)
        except Exception:
            pass
    
    def _show_log_context_menu(self, pos):
        """显示日志区域的右键菜单"""
        if not PYQT_AVAILABLE:
            return
        
        menu = QMenu(self.sync_log_text)
        
        # 复制选中文本
        copy_action = menu.addAction("复制")
        copy_action.triggered.connect(self.sync_log_text.copy)
        
        # 全选
        select_all_action = menu.addAction("全选")
        select_all_action.triggered.connect(self.sync_log_text.selectAll)
        
        menu.addSeparator()
        
        # 清空日志
        clear_action = menu.addAction("清空日志")
        clear_action.triggered.connect(self.sync_log_text.clear)
        
        # 在鼠标位置显示菜单
        menu.exec(self.sync_log_text.mapToGlobal(pos))
    

    def _show_tk_source_context_menu(self, event, tree):
        """显示Tkinter模式下的源文件夹右键菜单"""
        # 获取选中的项目
        selection = tree.selection()
        if not selection:
            return
            
        # 获取选中项目的值
        item = tree.item(selection[0])['values']
        if not item:
            return
            
        # 检查是否是文件夹
        if item[1] != "文件夹":
            return
            
        # 获取当前目录路径
        current_dir = self.folder_a_var.get()
        if not current_dir:
            return
            
        # 构建完整路径
        folder_name = item[0]
        folder_path = os.path.join(current_dir, folder_name)
        
        # 创建右键菜单
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="设为源文件夹 A", command=lambda: self._set_tk_source_folder(folder_path))
        
        # 显示菜单
        menu.post(event.x_root, event.y_root)
    
    def _show_tk_target_context_menu(self, event, tree):
        """显示Tkinter模式下的目标文件夹右键菜单"""
        # 获取选中的项目
        selection = tree.selection()
        if not selection:
            return
            
        # 获取选中项目的值
        item = tree.item(selection[0])['values']
        if not item:
            return
            
        # 检查是否是文件夹
        if item[1] != "文件夹":
            return
            
        # 获取当前目录路径
        current_dir = self.folder_b_var.get()
        if not current_dir:
            return
            
        # 构建完整路径
        folder_name = item[0]
        folder_path = os.path.join(current_dir, folder_name)
        
        # 创建右键菜单
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="设为目标文件夹 B", command=lambda: self._set_tk_target_folder(folder_path))
        
        # 显示菜单
        menu.post(event.x_root, event.y_root)
    
    def _set_tk_source_folder(self, folder_path):
        """在Tkinter模式下将选中的文件夹设为源文件夹A"""
        self.folder_a_var.set(folder_path)
        # 更新源文件夹内容显示
        self._update_tree_content(self.source_tree, folder_path)
        self._log_message(f"已设置源文件夹A: {folder_path}", source="sync")
    
    def _set_tk_target_folder(self, folder_path):
        """在Tkinter模式下将选中的文件夹设为目标文件夹B"""
        self.folder_b_var.set(folder_path)
        # 更新目标文件夹内容显示
        self._update_tree_content(self.target_tree, folder_path)
        self._log_message(f"已设置目标文件夹B: {folder_path}", source="sync")
    
    # ===== 文件夹搜身相关方法 =====
    def _browse_file_slimming_folder(self):
        """浏览并选择文件夹搜身的目标文件夹"""
        folder_path = QFileDialog.getExistingDirectory(self.window, "选择目标文件夹", "")
        if folder_path:
            self.file_slimming_folder_edit.setText(folder_path)
            self.start_file_slimming_button.setEnabled(True)
            
            # 连接表格选择事件
            self.file_slimming_files_table.itemSelectionChanged.connect(self._on_file_slimming_selection_changed)
    
    def _start_file_slimming(self):
        """开始扫描大文件"""
        import shutil
        folder_path = self.file_slimming_folder_edit.text()
        if not folder_path or not os.path.isdir(folder_path):
            QMessageBox.warning(self.window, "警告", "请选择有效的目标文件夹")
            return
        
        # 禁用相关按钮
        self.start_file_slimming_button.setEnabled(False)
        self.pause_file_slimming_button.setEnabled(True)
        self.stop_file_slimming_button.setEnabled(True)
        
        # 清空文件列表
        self.file_slimming_files_table.setRowCount(0)
        self.file_slimming_files = []
        
        # 更新状态栏
        self.status_bar.showMessage("开始扫描大文件...")
        
        # 创建并启动扫描线程
        self.file_slimming_thread = FileSlimmingThread(folder_path)
        
        # 连接进度更新信号到UI更新槽函数
        self.file_slimming_thread.progress_updated.connect(self._update_file_slimming_progress)
        self.file_slimming_thread.current_file_updated.connect(self._update_file_slimming_current_file)
        self.file_slimming_thread.result_ready.connect(self._display_file_slimming_results)
        
        # 开始扫描
        self.file_slimming_thread.start()
    
    def _toggle_pause_file_slimming(self):
        """切换文件夹搜身的暂停/继续状态"""
        if self.is_file_slimming_paused:
            self.file_slimming_thread.resume()
            self.pause_file_slimming_button.setText("暂停")
            self.status_bar.showMessage("继续扫描大文件...")
        else:
            self.file_slimming_thread.pause()
            self.pause_file_slimming_button.setText("继续")
            self.status_bar.showMessage("扫描大文件已暂停")
        self.is_file_slimming_paused = not self.is_file_slimming_paused
    
    def _stop_file_slimming(self):
        """停止文件夹搜身"""
        if self.file_slimming_thread:
            self.file_slimming_thread.stop()
            self.file_slimming_thread.wait()
            self.file_slimming_thread = None
        
        # 重置UI状态
        self._reset_file_slimming_ui()
        self.status_bar.showMessage("文件夹搜身已停止")
    
    def _update_file_slimming_progress(self, progress):
        """更新文件夹搜身进度条"""
        self.file_slimming_progress_bar.setValue(progress)
    
    def _update_file_slimming_current_file(self, file_path):
        """更新当前处理的文件路径"""
        self.file_slimming_current_file_label.setText(f"当前文件: {file_path}")
    
    def _display_file_slimming_results(self, files_data):
        """显示文件夹搜身结果"""
        # 保存结果数据
        self.file_slimming_files = files_data
        
        # 重置表格
        self.file_slimming_files_table.setRowCount(0)
        
        # 如果没有找到文件
        if not files_data:
            self.status_bar.showMessage("未找到文件")
            self._reset_file_slimming_ui()
            return
        
        # 临时禁用排序以提高性能
        self.file_slimming_files_table.setSortingEnabled(False)
        
        # 显示文件列表
        for file_info in files_data:
            row_position = self.file_slimming_files_table.rowCount()
            self.file_slimming_files_table.insertRow(row_position)
            
            # 设置文件名单元格
            filename_item = QTableWidgetItem(file_info["name"])
            self.file_slimming_files_table.setItem(row_position, 0, filename_item)
            
            # 设置文件路径单元格
            path_item = QTableWidgetItem(file_info["full_path"])
            self.file_slimming_files_table.setItem(row_position, 1, path_item)
            
            # 设置文件大小单元格
            size_item = SizeTableWidgetItem(self._format_file_size(file_info["size"]), file_info["size"])
            self.file_slimming_files_table.setItem(row_position, 2, size_item)
            
            # 设置修改时间单元格
            time_item = QTableWidgetItem(file_info["modified"])
            self.file_slimming_files_table.setItem(row_position, 3, time_item)
        
        # 重新启用排序并设置默认排序（按文件大小降序）
        self.file_slimming_files_table.setSortingEnabled(True)
        
        # 强制触发排序
        self.file_slimming_files_table.horizontalHeader().setSortIndicator(2, Qt.SortOrder.DescendingOrder)
        
        # 更新状态栏
        self.status_bar.showMessage(f"扫描完成: 找到 {len(files_data)} 个文件")
        
        # 重置UI状态
        self._reset_file_slimming_ui()
    
    def _on_file_slimming_selection_changed(self):
        """当文件列表选择变化时启用/禁用操作按钮"""
        has_selection = len(self.file_slimming_files_table.selectedItems()) > 0
        self.copy_selected_files_button.setEnabled(has_selection)
        self.move_selected_files_button.setEnabled(has_selection)
        self.delete_selected_files_button.setEnabled(has_selection)
    
    def _process_selected_files(self, operation_type):
        """处理选中的文件（复制或移动）"""
        import shutil
        selected_items = self.file_slimming_files_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self.window, "提示", "请先选择要处理的文件")
            return
        
        # 获取选中的文件路径
        selected_rows = set()
        for item in selected_items:
            selected_rows.add(item.row())
        
        # 选择目标文件夹
        target_folder = QFileDialog.getExistingDirectory(self.window, "选择目标文件夹", "")
        if not target_folder:
            return
        
        # 执行操作
        success_count = 0
        failed_count = 0
        operation_name = "复制" if operation_type == "copy" else "移动"
        
        for row in selected_rows:
            source_file = self.file_slimming_files_table.item(row, 1).text()
            filename = os.path.basename(source_file)
            target_file = os.path.join(target_folder, filename)
            
            # 如果目标文件已存在，询问是否覆盖
            if os.path.exists(target_file):
                reply = QMessageBox.question(
                    self.window,
                    "文件已存在",
                    f"文件 {filename} 已存在，是否覆盖？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Cancel:
                    break
                elif reply == QMessageBox.StandardButton.No:
                    failed_count += 1
                    continue
            
            try:
                if operation_type == "copy":
                    shutil.copy2(source_file, target_file)
                else:  # move
                    shutil.move(source_file, target_file)
                success_count += 1
            except Exception as e:
                self.logger.error(f"{operation_name}文件 {source_file} 失败: {e}")
                failed_count += 1
        
        # 更新状态栏
        self.status_bar.showMessage(f"{operation_name}完成: 成功 {success_count} 个文件, 失败 {failed_count} 个")
    
    def _delete_selected_files_from_slimming(self):
        """删除选中的文件"""
        selected_items = self.file_slimming_files_table.selectedItems()
        if not selected_items:
            QMessageBox.information(self.window, "提示", "请先选择要删除的文件")
            return
        
        # 获取选中的文件路径
        selected_rows = set()
        for item in selected_items:
            selected_rows.add(item.row())
        
        # 确认删除
        reply = QMessageBox.question(
            self.window,
            "确认删除",
            f"确定要删除选中的 {len(selected_rows)} 个文件吗？此操作无法撤销。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # 删除文件
        deleted_count = 0
        failed_count = 0
        for row in sorted(selected_rows, reverse=True):
            file_path = self.file_slimming_files_table.item(row, 1).text()
            try:
                # 检查文件是否存在
                if os.path.exists(file_path):
                    os.remove(file_path)
                    self.file_slimming_files_table.removeRow(row)
                    deleted_count += 1
                else:
                    # 文件不存在，仍然从表格中移除，但记录为失败
                    self.file_slimming_files_table.removeRow(row)
                    self.logger.warning(f"文件 {file_path} 不存在")
                    failed_count += 1
            except Exception as e:
                self.logger.error(f"删除文件 {file_path} 失败: {e}")
                failed_count += 1
        
        # 更新状态栏
        self.status_bar.showMessage(f"删除完成: 成功删除 {deleted_count} 个文件, 失败 {failed_count} 个")
    
    def _reset_file_slimming_ui(self):
        """重置文件夹搜身界面状态"""
        self.start_file_slimming_button.setEnabled(True)
        self.pause_file_slimming_button.setEnabled(False)
        self.stop_file_slimming_button.setEnabled(False)
        self.is_file_slimming_paused = False
        self.pause_file_slimming_button.setText("暂停")
    
    def _show_file_slimming_context_menu(self, position):
        """显示文件表格的右键菜单"""
        # 如果没有选中任何项目，则不显示菜单
        if not self.file_slimming_files_table.selectedItems():
            return
        
        # 创建右键菜单
        context_menu = QMenu()
        
        # 添加删除操作
        delete_action = QAction("删除选中文件", self.window)
        delete_action.triggered.connect(self._delete_selected_files_from_slimming)
        context_menu.addAction(delete_action)
        
        # 显示菜单
        context_menu.exec(self.file_slimming_files_table.mapToGlobal(position))
    
    # ===== 文件夹大小功能方法 =====
    
    def _browse_folder_size_folder(self):
        """浏览文件夹大小页面中的目标文件夹"""
        folder = QFileDialog.getExistingDirectory(self.window, "选择文件夹")
        if folder:
            self.folder_size_folder_edit.setText(folder)
            self.start_folder_size_button.setEnabled(True)
    
    def _start_folder_size(self):
        """开始计算文件夹大小"""
        folder = self.folder_size_folder_edit.text()
        if not folder:
            QMessageBox.warning(self.window, "警告", "请先选择文件夹")
            return
        
        if not os.path.exists(folder):
            QMessageBox.warning(self.window, "警告", "文件夹不存在")
            return
        
        # 清空表格
        self.folder_size_folders_table.setRowCount(0)
        self.folder_size_folders = []
        
        # 创建并启动线程
        self.folder_size_thread = FolderSizeThread(folder, self.sync_engine)
        self.folder_size_thread.progress_updated.connect(self._on_folder_size_progress_updated)
        self.folder_size_thread.current_folder_updated.connect(self._on_folder_size_current_folder_updated)
        self.folder_size_thread.result_ready.connect(self._on_folder_size_result_ready)
        self.folder_size_thread.log_updated.connect(self._on_folder_size_log_updated)
        
        self.folder_size_thread.start()
        
        # 更新按钮状态
        self.start_folder_size_button.setEnabled(False)
        self.pause_folder_size_button.setEnabled(True)
        self.stop_folder_size_button.setEnabled(True)
        self.is_folder_size_paused = False
        self.pause_folder_size_button.setText("暂停")
        
        # 禁用操作按钮
        self.copy_selected_folders_button.setEnabled(False)
        self.move_selected_folders_button.setEnabled(False)
        self.delete_selected_folders_button.setEnabled(False)
    
    def _toggle_pause_folder_size(self):
        """暂停/恢复文件夹大小计算"""
        if self.folder_size_thread is None:
            return
        
        if self.is_folder_size_paused:
            # 恢复
            self.folder_size_thread.resume()
            self.is_folder_size_paused = False
            self.pause_folder_size_button.setText("暂停")
        else:
            # 暂停
            self.folder_size_thread.pause()
            self.is_folder_size_paused = True
            self.pause_folder_size_button.setText("恢复")
    
    def _stop_folder_size(self):
        """停止文件夹大小计算"""
        if self.folder_size_thread is not None:
            self.folder_size_thread.stop()
            self.folder_size_thread = None
        
        # 重置UI状态
        self._reset_folder_size_ui()
    
    def _reset_folder_size_ui(self):
        """重置文件夹大小界面状态"""
        self.start_folder_size_button.setEnabled(True)
        self.pause_folder_size_button.setEnabled(False)
        self.stop_folder_size_button.setEnabled(False)
        self.is_folder_size_paused = False
        self.pause_folder_size_button.setText("暂停")
    
    def _on_folder_size_progress_updated(self, progress):
        """处理进度更新"""
        self.folder_size_progress_bar.setValue(progress)
    
    def _on_folder_size_current_folder_updated(self, folder_path):
        """处理当前文件夹更新"""
        self.folder_size_current_folder_label.setText(f"当前文件夹: {folder_path}")
    
    def _on_folder_size_result_ready(self, folder_list):
        """处理结果就绪"""
        self.folder_size_folders = folder_list
        
        # 临时禁用排序以提高性能
        self.folder_size_folders_table.setSortingEnabled(False)
        
        # 更新表格
        self.folder_size_folders_table.setRowCount(len(folder_list))
        for row, folder_info in enumerate(folder_list):
            # 文件夹名称
            name_item = QTableWidgetItem(folder_info["name"])
            self.folder_size_folders_table.setItem(row, 0, name_item)
            
            # 文件夹路径
            path_item = QTableWidgetItem(folder_info["path"])
            path_item.setData(Qt.ItemDataRole.UserRole, folder_info["path"])
            self.folder_size_folders_table.setItem(row, 1, path_item)
            
            # 文件夹大小
            size_str = self._format_file_size(folder_info["size"])
            size_item = SizeTableWidgetItem(size_str, folder_info["size"])
            self.folder_size_folders_table.setItem(row, 2, size_item)
            
            # 文件数量
            file_count_item = CountTableWidgetItem(str(folder_info["file_count"]), folder_info["file_count"])
            self.folder_size_folders_table.setItem(row, 3, file_count_item)
            
            # 修改时间
            modified_item = QTableWidgetItem(folder_info["modified"])
            self.folder_size_folders_table.setItem(row, 4, modified_item)
        
        # 重新启用排序并设置默认排序（按文件数量降序）
        self.folder_size_folders_table.setSortingEnabled(True)
        
        # 强制触发排序
        self.folder_size_folders_table.horizontalHeader().setSortIndicator(3, Qt.SortOrder.DescendingOrder)
        
        # 重置UI状态
        self._reset_folder_size_ui()
        
        # 启用操作按钮
        if folder_list:
            self.copy_selected_folders_button.setEnabled(True)
            self.move_selected_folders_button.setEnabled(True)
            self.delete_selected_folders_button.setEnabled(True)
    
    def _on_folder_size_log_updated(self, message):
        """处理日志更新"""
        self._log_message(message, source="folder_size")
    
    def _show_folder_size_context_menu(self, position):
        """显示文件夹表格的右键菜单"""
        # 如果没有选中任何项目，则不显示菜单
        if not self.folder_size_folders_table.selectedItems():
            return
        
        # 创建右键菜单
        context_menu = QMenu()
        
        # 添加复制操作
        copy_action = QAction("复制选中文件夹", self.window)
        copy_action.triggered.connect(lambda: self._process_selected_folders("copy"))
        context_menu.addAction(copy_action)
        
        # 添加移动操作
        move_action = QAction("移动选中文件夹", self.window)
        move_action.triggered.connect(lambda: self._process_selected_folders("move"))
        context_menu.addAction(move_action)
        
        # 添加删除操作
        delete_action = QAction("删除选中文件夹", self.window)
        delete_action.triggered.connect(self._delete_selected_folders)
        context_menu.addAction(delete_action)
        
        # 显示菜单
        context_menu.exec(self.folder_size_folders_table.mapToGlobal(position))
    
    def _process_selected_folders(self, operation):
        """处理选中的文件夹（复制/移动）"""
        selected_items = self.folder_size_folders_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.window, "警告", "请先选择文件夹")
            return
        
        # 获取选中的文件夹路径
        selected_rows = set(item.row() for item in selected_items)
        selected_folders = []
        for row in selected_rows:
            path_item = self.folder_size_folders_table.item(row, 1)
            if path_item:
                folder_path = path_item.data(Qt.ItemDataRole.UserRole)
                selected_folders.append(folder_path)
        
        if not selected_folders:
            return
        
        # 选择目标目录
        if operation == "copy":
            target_dir = QFileDialog.getExistingDirectory(self.window, "选择目标文件夹")
            if not target_dir:
                return
            
            # 复制文件夹
            success_count = 0
            failed_count = 0
            for folder_path in selected_folders:
                folder_name = os.path.basename(folder_path)
                dest_path = os.path.join(target_dir, folder_name)
                try:
                    self._copy_directory(folder_path, dest_path)
                    success_count += 1
                    self._log_message(f"复制文件夹成功: {folder_path} -> {dest_path}", source="folder_size")
                except Exception as e:
                    failed_count += 1
                    self._log_message(f"复制文件夹失败: {folder_path}, 错误: {str(e)}", source="folder_size")
            
            QMessageBox.information(self.window, "完成", f"复制完成: 成功 {success_count} 个, 失败 {failed_count} 个")
        
        elif operation == "move":
            target_dir = QFileDialog.getExistingDirectory(self.window, "选择目标文件夹")
            if not target_dir:
                return
            
            # 移动文件夹
            success_count = 0
            failed_count = 0
            for folder_path in selected_folders:
                folder_name = os.path.basename(folder_path)
                dest_path = os.path.join(target_dir, folder_name)
                copy_success = False
                try:
                    self._copy_directory(folder_path, dest_path)
                    copy_success = True
                    # 删除原文件夹
                    self._delete_directory(folder_path)
                    success_count += 1
                    self._log_message(f"移动文件夹成功: {folder_path} -> {dest_path}", source="folder_size")
                except Exception as e:
                    failed_count += 1
                    self._log_message(f"移动文件夹失败: {folder_path}, 错误: {str(e)}", source="folder_size")
                    # 如果复制失败，尝试删除可能已部分复制的目标文件夹
                    if not copy_success and os.path.exists(dest_path):
                        try:
                            self._delete_directory(dest_path)
                            self._log_message(f"已清理部分复制的内容: {dest_path}", source="folder_size")
                        except Exception as cleanup_error:
                            self._log_message(f"清理部分复制内容失败: {dest_path}, 错误: {str(cleanup_error)}", source="folder_size")
            
            QMessageBox.information(self.window, "完成", f"移动完成: 成功 {success_count} 个, 失败 {failed_count} 个")
            
            # 刷新列表
            self._start_folder_size()
    
    def _delete_selected_folders(self):
        """删除选中的文件夹"""
        selected_items = self.folder_size_folders_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self.window, "警告", "请先选择文件夹")
            return
        
        # 获取选中的文件夹路径
        selected_rows = set(item.row() for item in selected_items)
        selected_folders = []
        for row in selected_rows:
            path_item = self.folder_size_folders_table.item(row, 1)
            if path_item:
                folder_path = path_item.data(Qt.ItemDataRole.UserRole)
                selected_folders.append(folder_path)
        
        if not selected_folders:
            return
        
        # 确认删除
        reply = QMessageBox.question(
            self.window,
            "确认删除",
            f"确定要删除选中的 {len(selected_folders)} 个文件夹吗？\n此操作不可恢复！",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success_count = 0
            failed_count = 0
            for folder_path in selected_folders:
                try:
                    self._delete_directory(folder_path)
                    success_count += 1
                    self._log_message(f"删除文件夹成功: {folder_path}", source="folder_size")
                except Exception as e:
                    failed_count += 1
                    self._log_message(f"删除文件夹失败: {folder_path}, 错误: {str(e)}", source="folder_size")
            
            QMessageBox.information(self.window, "完成", f"删除完成: 成功 {success_count} 个, 失败 {failed_count} 个")
            
            # 刷新列表
            self._start_folder_size()
    
    def _copy_directory(self, src, dst):
        """递归复制目录"""
        try:
            if not os.path.exists(dst):
                os.makedirs(dst)
            for item in os.listdir(src):
                s = os.path.join(src, item)
                d = os.path.join(dst, item)
                if os.path.isdir(s):
                    self._copy_directory(s, d)
                else:
                    try:
                        copy_file(s, d)
                    except Exception as e:
                        self._log_message(f"无法复制文件 {s} 到 {d}: {str(e)}", source="folder_size")
        except Exception as e:
            self._log_message(f"复制目录时出错 {src}: {str(e)}", source="folder_size")
            raise
    
    def _delete_directory(self, path):
        """递归删除目录"""
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    self._delete_directory(item_path)
                else:
                    try:
                        os.unlink(item_path)
                    except (PermissionError, FileNotFoundError) as e:
                        self._log_message(f"无法删除文件 {item_path}: {str(e)}", source="folder_size")
            try:
                os.rmdir(path)
            except (PermissionError, OSError) as e:
                self._log_message(f"无法删除目录 {path}: {str(e)}", source="folder_size")
                raise
        except (PermissionError, FileNotFoundError, OSError) as e:
            self._log_message(f"删除目录时出错 {path}: {str(e)}", source="folder_size")
            raise
    
    def run(self):
        """运行应用"""
        try:
            if PYQT_AVAILABLE:
                print("PyQt is available, running GUI")
                # 确保应用程序实例被正确创建
                if self.app is None:
                    print("警告: self.app 为 None")
                    return 1
                # 确保主窗口被正确创建
                if self.window is None:
                    print("警告: self.window 为 None")
                    return 1
                
                # 显示窗口
                print("About to show window")
                self.window.show()
                print("Window shown in run method")
                
                # 设置应用程序退出前的清理操作
                def cleanup_on_exit():
                    print("[DEBUG] 开始应用程序退出清理")
                    # 确保清理线程资源
                    self._cleanup_thread_resources()
                    print("[DEBUG] 应用程序退出清理完成")
                
                # 连接关闭信号
                if hasattr(self.app, 'aboutToQuit'):
                    self.app.aboutToQuit.connect(cleanup_on_exit)
                
                # 运行应用程序事件循环
                print("About to call app.exec()")
                try:
                    # 使用sys.exit确保程序正确退出
                    result = self.app.exec()
                    print(f"app.exec() returned with code: {result}")
                    # 显式调用清理函数
                    cleanup_on_exit()
                    print("GUI已正常退出")
                    return result
                except Exception as e:
                    error_msg = f"Error in app.exec(): {e}"
                    print(error_msg)
                    # 即使发生异常，也要尝试清理
                    cleanup_on_exit()
                    # 尝试记录到日志
                    try:
                        import logging
                        logging.error(error_msg, exc_info=True)
                    except:
                        pass
                    return 1
            else:
                print("PyQt is not available, running Tkinter")
                self.root.mainloop()
        except Exception as e:
            error_msg = f"SyncApp.run() 执行出错: {e}"
            print(error_msg)
            # 尝试记录到日志
            try:
                import logging
                logging.error(error_msg, exc_info=True)
            except:
                pass
            return 1
