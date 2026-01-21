#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工作线程模块
用于文件夹管理工具（Myfile）
"""

import os
import sys
import threading
import logging
import hashlib
import concurrent.futures
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable, Set
from collections import defaultdict

try:
    from PyQt6.QtCore import (
        QObject as QtQObject, QThread as QtThread, pyqtSignal as qtSignal, 
        pyqtSlot, QDir as QtDDir, QSortFilterProxyModel as QtSortFilterProxyModel, 
        QTimer as QtTimer, Qt as QtQt
    )
    PYQT_AVAILABLE = True
    QThread = QtThread
    pyqtSignal = qtSignal
    QObject = QtQObject
except ImportError:
    PYQT_AVAILABLE = False
    QThread = None
    pyqtSignal = None
    QObject = None


class DummySignal:
    """在非PyQt模式下使用的空信号类"""

    def __init__(self, *args):
        pass

    def emit(self, *args):
        pass


ConditionalSignal = pyqtSignal if PYQT_AVAILABLE else DummySignal

BaseThread = QThread if (PYQT_AVAILABLE and QThread is not None) else threading.Thread

BaseObject = QObject if (PYQT_AVAILABLE and QObject is not None) else object


class FileSlimmingThread(BaseThread):
    """文件夹搜身线程 - 扫描大文件"""

    progress_updated = ConditionalSignal(int)
    current_file_updated = ConditionalSignal(str)
    result_ready = ConditionalSignal(list)
    log_updated = ConditionalSignal(str)

    def __init__(self, directory: str):
        """
        初始化文件夹搜身线程

        Args:
            directory: 要扫描的目录路径
        """
        super().__init__()
        self.directory = directory
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()

    def stop(self) -> None:
        """停止扫描"""
        self._stop_event.set()
        self._pause_event.set()
        if PYQT_AVAILABLE:
            self.wait()

    def pause(self) -> None:
        """暂停扫描"""
        self._pause_event.clear()

    def resume(self) -> None:
        """恢复扫描"""
        self._pause_event.set()

    def _emit_log(self, message: str) -> None:
        """发送日志信息"""
        if PYQT_AVAILABLE:
            self.log_updated.emit(message)

    def _emit_progress(self, progress: int) -> None:
        """发送进度更新"""
        if PYQT_AVAILABLE:
            self.progress_updated.emit(progress)

    def _emit_current_file(self, file_path: str) -> None:
        """发送当前处理的文件"""
        if PYQT_AVAILABLE:
            self.current_file_updated.emit(file_path)

    def _emit_results(self, file_list: List[Dict[str, Any]]) -> None:
        """发送扫描结果"""
        if PYQT_AVAILABLE:
            self.result_ready.emit(file_list)

    def run(self) -> None:
        """执行文件扫描"""
        try:
            self._emit_log(f"开始扫描文件夹: {self.directory}")
            file_list = []
            total_files = 0
            scanned_files = 0

            for root_dir, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return

                self._pause_event.wait()
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return

                total_files += len(files)

            for root_dir, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return

                self._pause_event.wait()
                if self._stop_event.is_set():
                    self._emit_log("扫描已取消")
                    return

                for file in files:
                    if self._stop_event.is_set():
                        self._emit_log("扫描已取消")
                        return

                    self._pause_event.wait()
                    if self._stop_event.is_set():
                        self._emit_log("扫描已取消")
                        return

                    file_path = os.path.join(root_dir, file)
                    try:
                        file_stats = os.stat(file_path)
                        file_size = file_stats.st_size
                        modified_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                        file_list.append({
                            "name": file,
                            "path": root_dir,
                            "size": file_size,
                            "modified": modified_time,
                            "full_path": file_path
                        })

                        self._emit_current_file(file_path)

                    except (FileNotFoundError, PermissionError) as e:
                        self._emit_log(f"无法访问文件: {file_path}, 错误: {str(e)}")
                    except Exception as e:
                        self._emit_log(f"处理文件时出错: {file_path}, 错误: {str(e)}")

                    scanned_files += 1
                    progress = (scanned_files / total_files) * 100 if total_files > 0 else 0
                    self._emit_progress(int(progress))

            file_list.sort(key=lambda x: x["size"], reverse=True)
            top_files = file_list[:100]

            if not self._stop_event.is_set():
                self._emit_log(f"扫描完成，共找到 {len(file_list)} 个文件，显示前100个大文件")
                self._emit_results(top_files)

        except Exception as e:
            self._emit_log(f"扫描过程中发生错误: {str(e)}")


class DuplicateFinderThread(BaseThread):
    """重复文件查找线程"""

    THREADS = 4
    HASH_ALGO = "md5"
    CHUNK_SIZE = 8192

    progress_updated = ConditionalSignal(int)
    log_updated = ConditionalSignal(str)
    duplicate_files_found = ConditionalSignal(list)
    current_file_updated = ConditionalSignal(str)

    def __init__(self, directory: str):
        """
        初始化重复文件查找线程

        Args:
            directory: 要扫描的目录路径
        """
        super().__init__()
        self.directory = directory
        self._stop_event = threading.Event()
        self._total_files = 0
        self._processed_files = 0
        self._hash_processed_files = 0
        self._hash_total_files = 0

    def stop(self) -> None:
        """停止扫描"""
        self._stop_event.set()
        if PYQT_AVAILABLE:
            self.wait()

    def _emit_log(self, message: str) -> None:
        """发送日志信息"""
        if PYQT_AVAILABLE:
            self.log_updated.emit(message)

    def _emit_progress(self, progress: int) -> None:
        """发送进度更新"""
        if PYQT_AVAILABLE:
            self.progress_updated.emit(progress)

    def _emit_current_file(self, file_path: str) -> None:
        """发送当前处理的文件"""
        if PYQT_AVAILABLE:
            self.current_file_updated.emit(file_path)

    def _emit_results(self, duplicate_groups: List[Dict[str, Any]]) -> None:
        """发送扫描结果"""
        if PYQT_AVAILABLE:
            self.duplicate_files_found.emit(duplicate_groups)

    def _file_hash(self, path: str, algo: str = "md5", chunk_size: int = 8192) -> Optional[str]:
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

    def _update_hash_progress(self) -> None:
        """更新哈希计算的进度"""
        if self._hash_total_files > 0:
            scan_progress = 50
            hash_progress = int((self._hash_processed_files / self._hash_total_files) * 50)
            total_progress = scan_progress + hash_progress
            self._emit_progress(total_progress)

    def run(self) -> None:
        """执行重复文件扫描"""
        try:
            self._emit_log(f"开始扫描目录: {self.directory}")

            self._total_files = 0
            for root, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    return
                self._total_files += len(files)

            self._emit_log(f"找到 {self._total_files} 个文件，开始按大小分组...")

            size_groups = defaultdict(list)
            self._processed_files = 0

            for root, _, files in os.walk(self.directory):
                if self._stop_event.is_set():
                    return

                for filename in files:
                    if self._stop_event.is_set():
                        return

                    file_path = os.path.join(root, filename)
                    try:
                        if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
                            continue

                        file_size = os.path.getsize(file_path)
                        if file_size == 0:
                            continue

                        file_modified_time = os.path.getmtime(file_path)

                        size_groups[file_size].append({
                            'path': file_path,
                            'size': file_size,
                            'modified_time': file_modified_time
                        })

                        self._processed_files += 1
                        progress = int((self._processed_files / self._total_files) * 50)
                        self._emit_progress(progress)
                        self._emit_current_file(file_path)

                    except Exception as e:
                        self._emit_log(f"处理文件 {file_path} 时出错: {str(e)}")

            self._emit_log("文件扫描完成，开始计算可能重复文件的哈希值...")

            self._hash_total_files = 0
            for size, files in size_groups.items():
                if len(files) > 1:
                    self._hash_total_files += len(files)

            if self._hash_total_files == 0:
                self._emit_progress(100)
                self._emit_log("未找到重复文件")
                self._emit_results([])
                return

            self._hash_processed_files = 0
            hash_groups = defaultdict(list)

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.THREADS) as executor:
                for size, files in size_groups.items():
                    if self._stop_event.is_set():
                        break

                    if len(files) < 2:
                        continue

                    future_to_file = {}
                    for file_info in files:
                        file_path = file_info['path']
                        future = executor.submit(self._file_hash, file_path, self.HASH_ALGO, self.CHUNK_SIZE)
                        future_to_file[future] = file_info

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
                            self._hash_processed_files += 1
                            self._update_hash_progress()
                            self._emit_current_file(file_path)

            duplicate_groups = []
            for file_hash, files in hash_groups.items():
                if len(files) > 1:
                    group_size = files[0]['size'] if files else 0
                    duplicate_groups.append({
                        'size': group_size,
                        'hash': file_hash,
                        'files': files
                    })

            self._emit_progress(100)
            self._emit_log(f"扫描完成，找到 {len(duplicate_groups)} 组重复文件（基于大小和内容哈希值）")
            self._emit_results(duplicate_groups)

        except Exception as e:
            self._emit_log(f"扫描过程中出错: {str(e)}")


class CopyFilesThread(BaseThread):
    """用于复制文件的线程"""

    copy_finished = ConditionalSignal(int, int)
    refresh_needed = ConditionalSignal()

    def __init__(self, ui_instance: Any, selected_indices: List[Any], direction: str, 
                 model: Any, source_model: Any, use_proxy: bool, 
                 source_dir: str, target_dir: str):
        """
        初始化复制文件线程

        Args:
            ui_instance: UI实例
            selected_indices: 选中的索引列表
            direction: 复制方向
            model: 代理模型
            source_model: 源模型
            use_proxy: 是否使用代理模型
            source_dir: 源目录
            target_dir: 目标目录
        """
        super().__init__()
        self.ui = ui_instance
        self.selected_indices = list(selected_indices)
        self.direction = direction
        self.model = model
        self.source_model = source_model
        self.use_proxy = use_proxy
        self.source_dir = source_dir
        self.target_dir = target_dir

    def run(self) -> None:
        """执行文件复制"""
        copied_count = 0
        failed_count = 0
        verified_count = 0
        verify_failed_count = 0

        try:
            for index in self.selected_indices:
                try:
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

                            try:
                                source_stat = os.stat(file_path)
                                dest_stat = os.stat(dest_path)

                                if source_stat.st_size == dest_stat.st_size:
                                    def get_file_md5(filepath: str) -> str:
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

            self.ui._log_message(f"复制验证结果: 成功 {verified_count} 个, 验证失败 {verify_failed_count} 个", source="sync")
            result_msg = f"复制完成: 成功 {copied_count} 个, 失败 {failed_count} 个"
            self.ui._log_message(result_msg, source="sync")

            if PYQT_AVAILABLE:
                try:
                    self.copy_finished.emit(copied_count, failed_count)
                    import time
                    time.sleep(0.5)
                    self.refresh_needed.emit()
                except Exception as signal_e:
                    self.ui._log_message(f"发出信号时出错: {str(signal_e)}", source="sync")
        except Exception as e:
            self.ui._log_message(f"复制线程运行时发生严重错误: {str(e)}", source="sync")
            import traceback
            self.ui._log_message(f"错误详情: {traceback.format_exc()}", source="sync")
            if PYQT_AVAILABLE:
                try:
                    self.copy_finished.emit(copied_count, failed_count)
                except Exception as emit_e:
                    self.ui._log_message(f"发出完成信号时出错: {str(emit_e)}", source="sync")
                finally:
                    try:
                        self.refresh_needed.emit()
                    except Exception as refresh_e:
                        self.ui._log_message(f"发出刷新信号时出错: {str(refresh_e)}", source="sync")


class SyncThread(BaseThread):
    """同步任务线程类"""

    progress_updated = ConditionalSignal(int)
    log_updated = ConditionalSignal(str)
    sync_completed = ConditionalSignal(bool)
    same_files_found = ConditionalSignal(list)
    current_file_updated = ConditionalSignal(str)

    def __init__(self, sync_engine: Any, dir_a: str, dir_b: str, 
                 task_type: str = "sync", sync_mode: str = "a_to_b", 
                 sync_delete: bool = False, ignore_patterns: Optional[List[str]] = None):
        """
        初始化同步线程

        Args:
            sync_engine: 同步引擎实例
            dir_a: 目录A路径
            dir_b: 目录B路径
            task_type: 任务类型（"sync" 或 "find_same"）
            sync_mode: 同步模式
            sync_delete: 是否删除
            ignore_patterns: 忽略模式列表
        """
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
        self.task_type = task_type
        self.sync_mode = sync_mode
        self.sync_delete = sync_delete
        self.ignore_patterns = ignore_patterns
        self.last_log_length = 0
        self._running = False
        self._window_valid = True

    def run(self) -> None:
        """运行同步任务或查找相同文件任务"""
        self.last_log_length = 0
        self._running = True

        success = False
        same_files = []

        try:
            if self.task_type == "find_same":
                same_files = self.sync_engine.find_same_files(
                    self.dir_a, 
                    self.dir_b, 
                    self.ignore_patterns,
                    show_duplicates=False
                )
                success = True
            else:
                success = self.sync_engine.run_sync(
                    self.dir_a, 
                    self.dir_b, 
                    self.sync_mode, 
                    self.sync_delete, 
                    self.ignore_patterns
                )
        except Exception as e:
            import traceback
            error_source = "find_same" if self.task_type == "find_same" else "sync"
            error_msg = f"{error_source}任务执行时发生错误: {str(e)}"
            tb_str = traceback.format_exc()
            success = False
            if hasattr(self, 'ui') and hasattr(self.ui, '_log_message'):
                self.ui._log_message(error_msg, source=error_source)
                self.ui._log_message(f"错误详情: {tb_str}", source=error_source)

        finally:
            self._stop_progress_timer()
            
            if self.task_type == "find_same" and self._running:
                try:
                    if PYQT_AVAILABLE:
                        self.same_files_found.emit(same_files)
                    else:
                        if self.same_files_callback:
                            self.same_files_callback(same_files)
                except Exception as signal_e:
                    error_msg = f"发送相同文件信号时出错: {str(signal_e)}"
                    if hasattr(self, 'ui') and hasattr(self.ui, '_log_message'):
                        self.ui._log_message(error_msg, source="find_same")

            self._running = False

            try:
                self.update_progress()
            except Exception as e:
                pass

            try:
                if PYQT_AVAILABLE:
                    self.sync_completed.emit(success)
                else:
                    if self.completed_callback:
                        self.completed_callback(success)
            except Exception as e:
                pass

    def stop(self) -> None:
        """安全停止线程"""
        self._stop_progress_timer()
        try:
            self._running = False

            if hasattr(self, 'sync_engine') and self.sync_engine:
                if hasattr(self.sync_engine, 'stop'):
                    self.sync_engine.stop()

            if PYQT_AVAILABLE and hasattr(self, 'wait'):
                if not self.wait(2000):
                    if hasattr(self, 'terminate'):
                        try:
                            self.terminate()
                            self.wait(1000)
                        except Exception as e:
                            pass
        except Exception as e:
            pass
    
    def _start_progress_timer(self) -> None:
        """启动进度更新定时器（仅用于非PyQt模式）"""
        self._progress_timer_running = True
        if not PYQT_AVAILABLE or QTimer is None:
            import threading
            self._progress_timer = threading.Thread(target=self._progress_loop, daemon=True)
            self._progress_timer.start()
    
    def _progress_loop(self) -> None:
        """进度更新循环（非PyQt模式）"""
        import time
        while self._progress_timer_running:
            try:
                self.update_progress()
            except Exception:
                pass
            time.sleep(0.2)
    
    def _stop_progress_timer(self) -> None:
        """停止进度更新定时器"""
        self._progress_timer_running = False
        self._window_valid = False
        if PYQT_AVAILABLE and hasattr(self, '_progress_timer') and self._progress_timer:
            try:
                self._progress_timer.stop()
                self._progress_timer.deleteLater()
            except Exception:
                pass
        elif hasattr(self, '_progress_timer') and self._progress_timer and isinstance(self._progress_timer, threading.Thread):
            self._progress_timer.join(timeout=1)
    
    def _update_progress_periodically(self) -> None:
        """定期更新进度"""
        try:
            if not self._window_valid or not self._running:
                return
            if not hasattr(self, 'sync_engine') or not self.sync_engine:
                return
            progress = self.sync_engine.get_progress()
            if hasattr(self, 'progress_updated'):
                self.progress_updated.emit(progress)
            
            current_file = ""
            if hasattr(self.sync_engine, '_current_file'):
                current_file = self.sync_engine._current_file
            if current_file and hasattr(self, 'current_file_updated'):
                self.current_file_updated.emit(current_file)
        except Exception:
            pass

    def update_progress(self) -> None:
        """更新进度和日志"""
        try:
            if not self._window_valid:
                return
            if not hasattr(self, 'sync_engine') or not self.sync_engine or not self._running:
                return

            progress = self.sync_engine.get_progress()
            current_file = ""
            if hasattr(self.sync_engine, '_current_file'):
                current_file = self.sync_engine._current_file

            if PYQT_AVAILABLE:
                try:
                    if hasattr(self, 'progress_updated'):
                        self.progress_updated.emit(progress)
                except Exception as e:
                    pass

                if current_file and hasattr(self, 'current_file_updated'):
                    try:
                        self.current_file_updated.emit(current_file)
                    except Exception as e:
                        pass
            else:
                if hasattr(self, 'progress_callback') and self.progress_callback:
                    try:
                        self.progress_callback(progress)
                    except Exception as e:
                        pass
                if current_file and hasattr(self, 'current_file_callback') and self.current_file_callback:
                    try:
                        self.current_file_callback(current_file)
                    except Exception as e:
                        pass
        except Exception as e:
            pass

        try:
            if not self._window_valid:
                return
            if hasattr(self, 'sync_engine') and self.sync_engine:
                logs = self.sync_engine.get_log()
                if logs and len(logs) > self.last_log_length:
                    new_logs = logs[self.last_log_length:]
                    for log in new_logs:
                        try:
                            source = "find_same" if self.task_type == "find_same" else "sync"
                            if PYQT_AVAILABLE and hasattr(self, 'log_updated'):
                                self.log_updated.emit(log)
                            elif hasattr(self, 'log_callback') and self.log_callback:
                                if source == "find_same":
                                    self.log_callback(log, source="find_same")
                                else:
                                    self.log_callback(log)
                        except Exception as e:
                            pass
                    self.last_log_length = len(logs)
        except Exception as e:
            pass
