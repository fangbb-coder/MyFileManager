#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
同步核心逻辑模块
用于文件夹管理工具（Myfile）
"""

import os
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from utils import (
    get_file_info, copy_file, delete_file, delete_directory,
    should_ignore_file, format_timestamp, parse_ignore_patterns,
    compare_files
)


class SyncEngine:
    """
    文件同步引擎类
    实现单向和双向同步功能
    """
    
    def __init__(self) -> None:
        self._stop_requested = False
        self._pause_requested = False
        self._current_progress = 0
        self._total_files = 0
        self._processed_files = 0
        self._sync_log: List[str] = []
        self._current_file = ""
        self._log_file_handle: Optional[Any] = None
        self._log_file_path = os.path.join(os.getcwd(), "log.txt")
    
    def stop(self) -> None:
        """停止同步任务"""
        self._stop_requested = True
        self._log_message("同步任务已停止")
        if self._log_file_handle is not None:
            try:
                self._log_file_handle.close()
                self._log_file_handle = None
            except Exception as e:
                logging.error(f"关闭日志文件失败: {str(e)}")
    
    def pause(self) -> None:
        """暂停同步任务"""
        self._pause_requested = True
        self._log_message("同步任务已暂停")
    
    def resume(self) -> None:
        """恢复同步任务"""
        self._pause_requested = False
        self._log_message("同步任务已恢复")
    
    def is_stopped(self) -> bool:
        """检查是否已停止"""
        return self._stop_requested
    
    def is_paused(self) -> bool:
        """检查是否已暂停"""
        return self._pause_requested
    
    def get_progress(self) -> int:
        """获取同步进度"""
        if self._total_files == 0:
            return 0
        return min(100, int((self._processed_files / self._total_files) * 100))
    
    def get_log(self) -> List[str]:
        """获取同步日志"""
        return self._sync_log
    
    def clear_log(self) -> None:
        """清空同步日志"""
        self._sync_log = []
    
    def _log_message(self, message: Any, log_type: str = "info") -> None:
        """
        记录日志信息
        
        Args:
            message: 日志消息
            log_type: 日志类型 (info, warning, error)
        """
        try:
            safe_message = str(message).encode('utf-8', errors='ignore').decode('utf-8')
            timestamp = format_timestamp()
            log_entry = f"[{timestamp}] {safe_message}"
            self._sync_log.append(log_entry)
            
            if log_type == "info":
                logging.info(safe_message)
            elif log_type == "warning":
                logging.warning(safe_message)
            elif log_type == "error":
                logging.error(safe_message)
            
            try:
                if self._log_file_handle is None:
                    self._log_file_handle = open(self._log_file_path, 'a', encoding='utf-8', errors='ignore')
                self._log_file_handle.write(f"{log_entry}\n")
                self._log_file_handle.flush()
            except Exception as e:
                logging.error(f"写入日志文件失败: {str(e)}")
        except Exception as e:
            logging.error(f"日志记录失败: {str(e)}")
    
    def _check_pause_stop(self) -> bool:
        """检查是否需要暂停或停止"""
        if self._stop_requested:
            return False
        
        while self._pause_requested and not self._stop_requested:
            time.sleep(0.5)
        
        return not self._stop_requested
    
    def _scan_files(self, root_dir: str, ignore_patterns: Optional[List[str]] = None, compute_hash: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        扫描目录中的所有文件
        
        Args:
            root_dir: 根目录路径
            ignore_patterns: 忽略模式列表
            compute_hash: 是否计算文件哈希值
        
        Returns:
            dict: 文件路径映射到文件信息的字典
        """
        files_info = {}
        
        if not os.path.exists(root_dir):
            return files_info
        
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # 过滤掉应该忽略的文件
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                if not should_ignore_file(file_path, ignore_patterns):
                    # 计算相对路径作为键
                    rel_path = os.path.relpath(file_path, root_dir)
                    file_info = get_file_info(file_path, compute_hash=compute_hash)
                    if file_info:  # 添加检查，确保文件信息有效
                        files_info[rel_path] = file_info
            
            # 过滤掉应该忽略的目录
            dirnames[:] = [d for d in dirnames 
                          if not should_ignore_file(os.path.join(dirpath, d), ignore_patterns)]
            
            # 检查是否需要停止
            if self._stop_requested:
                return {}
        
        return files_info
    
    def _scan_directories(self, root_dir: str, ignore_patterns: Optional[List[str]] = None) -> Set[str]:
        """
        扫描目录中的所有目录（包括空目录）
        
        Args:
            root_dir: 根目录路径
            ignore_patterns: 忽略模式列表
        
        Returns:
            set: 目录相对路径的集合
        """
        dirs_set: Set[str] = set()
        
        if not os.path.exists(root_dir):
            return dirs_set
        
        # 添加根目录本身
        dirs_set.add('.')
        
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # 过滤掉应该忽略的目录
            dirnames[:] = [d for d in dirnames 
                          if not should_ignore_file(os.path.join(dirpath, d), ignore_patterns)]
            
            # 添加当前目录下的所有子目录
            for dirname in dirnames:
                dir_path = os.path.join(dirpath, dirname)
                rel_path = os.path.relpath(dir_path, root_dir)
                dirs_set.add(rel_path)
            
            # 检查是否需要停止
            if self._stop_requested:
                return set()
        
        return dirs_set
    
    def sync_one_way(self, source_dir: str, dest_dir: str, sync_delete: bool = False, ignore_patterns: Optional[List[str]] = None) -> bool:
        """
        单向同步
        
        Args:
            source_dir: 源目录
            dest_dir: 目标目录
            sync_delete: 是否同步删除
            ignore_patterns: 忽略模式列表
        
        Returns:
            bool: 同步是否成功
        """
        try:
            self._stop_requested = False
            self._pause_requested = False
            self._current_progress = 0
            self._processed_files = 0
            self._sync_log = []
            
            self._log_message(f"开始同步: {source_dir} -> {dest_dir}")
            
            # 解析忽略模式
            if isinstance(ignore_patterns, str):
                ignore_patterns = parse_ignore_patterns(ignore_patterns)
            
            # 扫描源目录和目标目录
            self._log_message("正在扫描源目录...")
            if not self._check_pause_stop():
                return False
            
            source_files = self._scan_files(source_dir, ignore_patterns)
            if self._stop_requested:
                return False
            
            self._log_message("正在扫描目标目录...")
            if not self._check_pause_stop():
                return False
            
            dest_files = self._scan_files(dest_dir, ignore_patterns)
            if self._stop_requested:
                return False
            
            # 计算总文件数
            self._total_files = max(len(source_files), len(dest_files))
            
            # 执行同步
            operations = 0
            
            # 1. 复制或更新文件
            for rel_path, source_info in source_files.items():
                if not self._check_pause_stop():
                    return False
                
                dest_path = os.path.join(dest_dir, rel_path)
                
                if rel_path not in dest_files:
                    # 文件不存在，需要复制
                    self._log_message(f"复制文件: {rel_path}")
                    if copy_file(source_info['path'], dest_path):
                        operations += 1
                else:
                    # 文件存在，检查是否需要更新
                    dest_info = dest_files[rel_path]
                    if source_info['mtime'] > dest_info['mtime'] or source_info['size'] != dest_info['size']:
                        self._log_message(f"更新文件: {rel_path}")
                        if copy_file(source_info['path'], dest_path, overwrite=True):
                            operations += 1
                
                self._processed_files += 1
            
            # 2. 同步删除（如果启用）- 删除多余的文件和文件夹
            if sync_delete:
                # 扫描源目录和目标目录的目录结构
                source_dirs = self._scan_directories(source_dir, ignore_patterns)
                dest_dirs = self._scan_directories(dest_dir, ignore_patterns)
                
                # 删除多余的文件
                for rel_path, dest_info in dest_files.items():
                    if not self._check_pause_stop():
                        return False
                    
                    if rel_path not in source_files:
                        dest_path = dest_info['path']
                        if os.path.isfile(dest_path):
                            self._log_message(f"删除文件: {rel_path}")
                            if delete_file(dest_path):
                                operations += 1
                    
                    self._processed_files += 1
                
                # 删除多余的文件夹（从深到浅删除，避免删除父目录时子目录已不存在）
                dirs_to_delete = []
                for rel_dir in dest_dirs:
                    if rel_dir not in source_dirs:
                        # 跳过根目录
                        if rel_dir == '.':
                            continue
                        dest_dir_path = os.path.join(dest_dir, rel_dir)
                        if os.path.exists(dest_dir_path) and os.path.isdir(dest_dir_path):
                            dirs_to_delete.append((rel_dir, dest_dir_path))
                
                # 按路径深度排序，从深到浅删除
                dirs_to_delete.sort(key=lambda x: x[0].count(os.sep), reverse=True)
                for rel_dir, dest_dir_path in dirs_to_delete:
                    if not self._check_pause_stop():
                        return False
                    if os.path.exists(dest_dir_path):
                        self._log_message(f"删除文件夹: {rel_dir}")
                        if delete_directory(dest_dir_path):
                            operations += 1
            
            self._log_message(f"同步完成。执行操作数: {operations}")
            return True
            
        except Exception as e:
            self._log_message(f"同步过程中发生错误: {str(e)}", "error")
            return False
    
    def sync_two_way(self, dir_a: str, dir_b: str, sync_delete: bool = False, ignore_patterns: Optional[List[str]] = None) -> bool:
        """
        双向同步（优化版本）
        
        Args:
            dir_a: 目录A
            dir_b: 目录B
            sync_delete: 是否同步删除
            ignore_patterns: 忽略模式列表
        
        Returns:
            bool: 同步是否成功
        """
        try:
            self._stop_requested = False
            self._pause_requested = False
            self._current_progress = 0
            self._processed_files = 0
            self._sync_log = []
            
            self._log_message(f"开始双向同步: {dir_a} ↔ {dir_b}")
            
            # 解析忽略模式
            if isinstance(ignore_patterns, str):
                ignore_patterns = parse_ignore_patterns(ignore_patterns)
            
            # 扫描两个目录
            self._log_message("正在扫描目录A...")
            if not self._check_pause_stop():
                return False
            
            files_a = self._scan_files(dir_a, ignore_patterns)
            if self._stop_requested:
                return False
            
            self._log_message("正在扫描目录B...")
            if not self._check_pause_stop():
                return False
            
            files_b = self._scan_files(dir_b, ignore_patterns)
            if self._stop_requested:
                return False
            
            # 计算总文件数
            self._total_files = max(len(files_a), len(files_b)) * 2
            
            # 执行双向同步
            operations = 0
            conflicts = []
            
            # 1. A → B 的同步
            for rel_path, info_a in files_a.items():
                if not self._check_pause_stop():
                    return False
                
                if rel_path not in files_b:
                    # A有B没有，复制到B
                    dest_path = os.path.join(dir_b, rel_path)
                    self._log_message(f"从A复制到B: {rel_path}")
                    if copy_file(info_a['path'], dest_path):
                        operations += 1
                else:
                    # 两边都有，检查是否需要更新
                    info_b = files_b[rel_path]
                    if info_a['mtime'] > info_b['mtime']:
                        # A较新，复制到B
                        dest_path = os.path.join(dir_b, rel_path)
                        self._log_message(f"A较新，更新到B: {rel_path}")
                        if copy_file(info_a['path'], dest_path, overwrite=True):
                            operations += 1
                    elif info_b['mtime'] > info_a['mtime']:
                        # B较新，需要在B→A同步时处理
                        pass
                    elif info_a['size'] != info_b['size']:
                        # 时间相同但大小不同，记录冲突
                        conflicts.append(rel_path)
                        self._log_message(f"警告：文件冲突（时间相同但大小不同）: {rel_path}", "warning")
                
                self._processed_files += 1
            
            # 2. B → A 的同步
            for rel_path, info_b in files_b.items():
                if not self._check_pause_stop():
                    return False
                
                if rel_path not in files_a:
                    # B有A没有，复制到A
                    dest_path = os.path.join(dir_a, rel_path)
                    self._log_message(f"从B复制到A: {rel_path}")
                    if copy_file(info_b['path'], dest_path):
                        operations += 1
                else:
                    # 两边都有，检查是否需要更新
                    info_a = files_a[rel_path]
                    if info_b['mtime'] > info_a['mtime']:
                        # B较新，复制到A
                        dest_path = os.path.join(dir_a, rel_path)
                        self._log_message(f"B较新，更新到A: {rel_path}")
                        if copy_file(info_b['path'], dest_path, overwrite=True):
                            operations += 1
                
                self._processed_files += 1
            
            # 3. 同步删除（如果启用）- 优化后的安全策略
            if sync_delete:
                # 找出只在一个目录中存在的文件
                only_in_a = set(rel_path for rel_path in files_a if rel_path not in files_b)
                only_in_b = set(rel_path for rel_path in files_b if rel_path not in files_a)
                
                if only_in_a or only_in_b:
                    self._log_message(f"发现同步差异: A中有{len(only_in_a)}个唯一文件，B中有{len(only_in_b)}个唯一文件")
                    
                    # 为安全起见，记录差异但不自动删除，让用户决定
                    if only_in_a:
                        self._log_message(f"注意：目录A中有{len(only_in_a)}个文件在B中不存在", "warning")
                        for rel_path in list(only_in_a)[:5]:  # 只显示前5个
                            self._log_message(f"  A独有: {rel_path}", "warning")
                        if len(only_in_a) > 5:
                            self._log_message(f"  ... 还有{len(only_in_a) - 5}个文件", "warning")
                    
                    if only_in_b:
                        self._log_message(f"注意：目录B中有{len(only_in_b)}个文件在A中不存在", "warning")
                        for rel_path in list(only_in_b)[:5]:  # 只显示前5个
                            self._log_message(f"  B独有: {rel_path}", "warning")
                        if len(only_in_b) > 5:
                            self._log_message(f"  ... 还有{len(only_in_b) - 5}个文件", "warning")
            
            # 4. 报告冲突
            if conflicts:
                self._log_message(f"发现 {len(conflicts)} 个文件冲突", "warning")
                for conflict in conflicts[:10]:
                    self._log_message(f"冲突文件: {conflict}", "warning")
                if len(conflicts) > 10:
                    self._log_message(f"... 还有{len(conflicts) - 10}个冲突文件", "warning")
            
            self._log_message(f"双向同步完成。执行操作数: {operations}")
            return True
            
        except Exception as e:
            self._log_message(f"双向同步过程中发生错误: {str(e)}", "error")
            return False
    
    def find_same_files(self, dir_a: str, dir_b: str, ignore_patterns: Optional[List[str]] = None, show_duplicates: bool = False) -> List[Tuple[str, str]]:
        """
        查找两个目录中的相同文件
        
        Args:
            dir_a: 目录A路径
            dir_b: 目录B路径
            ignore_patterns: 忽略模式列表
            show_duplicates: 是否显示重复项
        
        Returns:
            list: 相同文件列表，每个元素是包含两个文件路径的元组
        """
        try:
            self._stop_requested = False
            self._pause_requested = False
            self._current_progress = 0
            self._processed_files = 0
            self._sync_log = []
            
            self._log_message(f"========== 开始查找相同文件 ==========")
            self._log_message(f"比对目录: {dir_a} <-> {dir_b}")
            self._log_message(f"忽略模式: {ignore_patterns if ignore_patterns else '无'}")
            self._log_message(f"显示重复项: {show_duplicates}")
            
            # 解析忽略模式
            if isinstance(ignore_patterns, str):
                ignore_patterns = parse_ignore_patterns(ignore_patterns)
                self._log_message(f"已解析忽略模式: {ignore_patterns}")
            
            # 扫描两个目录
            self._log_message(f"[步骤1/3] 正在扫描目录A - {dir_a}")
            if not self._check_pause_stop():
                self._log_message("操作已暂停或停止")
                return []
            
            files_a = self._scan_files(dir_a, ignore_patterns, compute_hash=True)
            if self._stop_requested:
                self._log_message("操作已停止")
                return []
            
            self._log_message(f"目录A扫描完成！共发现 {len(files_a)} 个文件")
            
            self._log_message(f"[步骤1/3] 正在扫描目录B - {dir_b}")
            if not self._check_pause_stop():
                self._log_message("操作已暂停或停止")
                return []
            
            files_b = self._scan_files(dir_b, ignore_patterns, compute_hash=True)
            if self._stop_requested:
                self._log_message("操作已停止")
                return []
            
            self._log_message(f"目录B扫描完成！共发现 {len(files_b)} 个文件")
            
            # 计算总文件数
            self._total_files = len(files_a) + len(files_b)
            self._log_message(f"总计文件数: {self._total_files} (目录A: {len(files_a)}, 目录B: {len(files_b)})")
            
            # 查找相同文件
            self._log_message(f"[步骤2/3] 开始构建文件映射，准备比对...")
            
            # 按文件大小和哈希分组（不包含文件名，以识别不同文件名的相同内容文件）
            file_map_a = {}
            file_map_b = {}
            
            # 构建文件A的映射
            self._log_message(f"[步骤2/3] 正在构建目录A文件映射... (共{len(files_a)}个文件)")
            a_count = 0
            for rel_path, info in files_a.items():
                if not self._check_pause_stop():
                    self._log_message("操作已暂停或停止")
                    return []
                
                # 使用文件大小和哈希作为key，识别相同内容但不同文件名的文件
                key = (info['size'], info['hash'])
                if key not in file_map_a:
                    file_map_a[key] = []
                file_map_a[key].append(info['path'])
                
                a_count += 1
                self._processed_files += 1
                
                # 实时更新进度，增加更新频率
                if a_count % 50 == 0:  # 每50个文件更新一次进度
                    progress = (a_count / len(files_a)) * 100
                    self._log_message(f"[目录A] 构建进度: {progress:.1f}% ({a_count}/{len(files_a)} 文件)")
            
            self._log_message(f"[步骤2/3] 目录A文件映射构建完成！共 {len(file_map_a)} 个唯一文件组")
            
            # 构建文件B的映射
            self._log_message(f"[步骤2/3] 正在构建目录B文件映射... (共{len(files_b)}个文件)")
            b_count = 0
            for rel_path, info in files_b.items():
                if not self._check_pause_stop():
                    self._log_message("操作已暂停或停止")
                    return []
                
                # 使用文件大小和哈希作为key，识别相同内容但不同文件名的文件
                key = (info['size'], info['hash'])
                if key not in file_map_b:
                    file_map_b[key] = []
                file_map_b[key].append(info['path'])
                
                b_count += 1
                self._processed_files += 1
                
                # 实时更新进度，增加更新频率
                if b_count % 50 == 0:  # 每50个文件更新一次进度
                    progress = (b_count / len(files_b)) * 100
                    self._log_message(f"[目录B] 构建进度: {progress:.1f}% ({b_count}/{len(files_b)} 文件)")
            
            self._log_message(f"[步骤2/3] 目录B文件映射构建完成！共 {len(file_map_b)} 个唯一文件组")
            
            same_files = []
            found_count = 0
            
            # 查找相同文件
            self._log_message(f"[步骤3/3] 开始比对文件... (目录A: {len(file_map_a)}组, 目录B: {len(file_map_b)}组)")
            total_keys = len(file_map_a)
            processed_keys = 0
            
            for key in file_map_a:
                if not self._check_pause_stop():
                    self._log_message("操作已暂停或停止")
                    return []
                
                processed_keys += 1
                
                if key in file_map_b:
                    file_size = key[0]
                    file_hash = key[1]
                    
                    # 记录找到匹配的文件组
                    self._log_message(f"[匹配] 找到相同文件组: 大小={file_size}字节, 哈希={file_hash[:8]}...")
                    
                    for path_a in file_map_a[key]:
                        for path_b in file_map_b[key]:
                            found_count += 1
                            same_files.append((path_a, path_b))
                            
                            # 实时记录发现的相同文件
                            self._log_message(f"  → 发现相同文件 #{found_count}: {os.path.basename(path_a)} ({file_size}字节)")
                            self._log_message(f"    A: {path_a}")
                            self._log_message(f"    B: {path_b}")
                
                # 更新进度，增加更新频率
                if processed_keys % 5 == 0 or processed_keys == total_keys:  # 每5个key或最后更新一次进度
                    progress = (processed_keys / total_keys) * 100
                    self._log_message(f"[步骤3/3] 比对进度: {progress:.1f}% ({processed_keys}/{total_keys} 组)，已发现 {found_count} 对相同文件")
            
            # 过滤重复项（如果需要）
            final_files = same_files
            if not show_duplicates and same_files:
                self._log_message(f"[步骤3/3] 正在过滤重复项... 原始相同文件数: {len(same_files)}")
                filtered_files = []
                seen_pairs = set()
                
                filter_count = 0
                for pair in same_files:
                    # 使用排序后的元组来避免重复
                    sorted_pair = tuple(sorted(pair))
                    if sorted_pair not in seen_pairs:
                        seen_pairs.add(sorted_pair)
                        filtered_files.append(pair)
                    else:
                        filter_count += 1
                        # 记录被过滤的重复项
                        if filter_count <= 10:  # 最多记录10条过滤信息，避免日志过多
                            self._log_message(f"  [过滤] 重复项: {pair[0]} <-> {pair[1]}")
                
                if filter_count > 10:
                    self._log_message(f"  [过滤] ... 还有 {filter_count - 10} 个重复项被过滤")
                    
                final_files = filtered_files
                self._log_message(f"[步骤3/3] 重复项过滤完成！最终相同文件数: {len(final_files)} (过滤了 {filter_count} 个重复项)")
                
                # 最终结果日志
                self._log_message(f"[完成] 相同文件查找完成，过滤后共发现 {len(final_files)} 对相同文件")
            else:
                # 最终结果日志
                self._log_message(f"[完成] 相同文件查找完成，共发现 {len(same_files)} 对相同文件")
            
            # 总结信息
            self._log_message(f"========== 相同文件查找任务完成 ==========")
            self._log_message(f"比对目录: {dir_a} <-> {dir_b}")
            self._log_message(f"总计处理文件: {self._total_files} 个")
            self._log_message(f"最终发现相同文件: {len(final_files)} 对")
            self._log_message(f"=======================================\n")
            
            return final_files
            
        except Exception as e:
            self._log_message(f"[错误] 查找相同文件过程中发生错误: {str(e)}", "error")
            self._log_message("=======================================\n")
            return []
    
    def run_sync(self, dir_a: str, dir_b: str, sync_mode: str = "a_to_b", sync_delete: bool = False, ignore_patterns: Optional[List[str]] = None) -> bool:
        """
        运行同步任务
        
        Args:
            dir_a: 目录A
            dir_b: 目录B
            sync_mode: 同步模式 (a_to_b, b_to_a, two_way)
            sync_delete: 是否同步删除
            ignore_patterns: 忽略模式列表
        
        Returns:
            bool: 同步是否成功
        """
        if sync_mode == "a_to_b":
            return self.sync_one_way(dir_a, dir_b, sync_delete, ignore_patterns)
        elif sync_mode == "b_to_a":
            return self.sync_one_way(dir_b, dir_a, sync_delete, ignore_patterns)
        elif sync_mode == "two_way":
            return self.sync_two_way(dir_a, dir_b, sync_delete, ignore_patterns)
        else:
            self._log_message(f"不支持的同步模式: {sync_mode}", "error")
            return False
    
    def calculate_folder_sizes(self, root_dir, ignore_patterns=None):
        """
        计算指定目录下所有文件夹的大小
        
        Args:
            root_dir: 根目录路径
            ignore_patterns: 忽略模式列表
        
        Returns:
            list: 文件夹信息列表，每个元素包含文件夹名称、路径、大小、修改时间等信息
        """
        try:
            self._stop_requested = False
            self._pause_requested = False
            self._current_progress = 0
            self._processed_files = 0
            self._sync_log = []
            
            self._log_message(f"开始计算文件夹大小: {root_dir}")
            
            if not os.path.exists(root_dir):
                self._log_message(f"目录不存在: {root_dir}", "error")
                return []
            
            # 解析忽略模式
            if isinstance(ignore_patterns, str):
                ignore_patterns = parse_ignore_patterns(ignore_patterns)
            
            folder_sizes = []
            
            # 遍历所有子文件夹
            for dirpath, dirnames, filenames in os.walk(root_dir):
                if self._stop_requested:
                    self._log_message("操作已停止")
                    return []
                
                # 检查是否暂停
                while self._pause_requested and not self._stop_requested:
                    import time
                    time.sleep(0.5)
                
                if self._stop_requested:
                    return []
                
                # 过滤掉应该忽略的目录
                dirnames[:] = [d for d in dirnames 
                              if not should_ignore_file(os.path.join(dirpath, d), ignore_patterns)]
                
                # 计算当前文件夹的大小
                folder_size = 0
                file_count = 0
                
                for filename in filenames:
                    if should_ignore_file(os.path.join(dirpath, filename), ignore_patterns):
                        continue
                    
                    file_path = os.path.join(dirpath, filename)
                    try:
                        file_size = os.path.getsize(file_path)
                        folder_size += file_size
                        file_count += 1
                    except (FileNotFoundError, PermissionError):
                        pass
                
                # 获取文件夹信息
                folder_name = os.path.basename(dirpath)
                folder_modified_time = os.path.getmtime(dirpath)
                
                # 添加到结果列表
                folder_sizes.append({
                    "name": folder_name,
                    "path": dirpath,
                    "size": folder_size,
                    "file_count": file_count,
                    "modified_time": folder_modified_time,
                    "modified": datetime.fromtimestamp(folder_modified_time).strftime('%Y-%m-%d %H:%M:%S')
                })
                
                self._processed_files += 1
            
            # 按文件夹大小排序（从大到小）
            folder_sizes.sort(key=lambda x: x["size"], reverse=True)
            
            self._log_message(f"计算完成，共找到 {len(folder_sizes)} 个文件夹")
            return folder_sizes
            
        except Exception as e:
            self._log_message(f"计算文件夹大小时发生错误: {str(e)}", "error")
            return []
