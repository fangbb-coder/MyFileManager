#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件比较与复制工具函数
用于文件夹管理工具（Myfile）
"""

import os
import shutil
import hashlib
import logging
from datetime import datetime


def get_file_hash(file_path, block_size=65536):
    """
    计算文件的MD5哈希值，用于文件内容比较
    
    Args:
        file_path: 文件路径
        block_size: 读取块大小
    
    Returns:
        str: 文件的MD5哈希值
    """
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as file:
            buf = file.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = file.read(block_size)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"计算文件哈希值失败 {file_path}: {str(e)}")
        return None


def get_file_info(file_path):
    """
    获取文件的基本信息，包括文件哈希值
    
    Args:
        file_path: 文件路径
    
    Returns:
        dict: 包含文件名、大小、修改时间、哈希值和路径的字典
    """
    try:
        stat_info = os.stat(file_path)
        # 计算文件哈希值
        hash_value = get_file_hash(file_path)
        if hash_value is None:
            # 如果无法计算哈希值，返回None表示失败
            return None
        
        return {
            'name': os.path.basename(file_path),
            'size': stat_info.st_size,
            'mtime': stat_info.st_mtime,
            'hash': hash_value,
            'path': file_path
        }
    except Exception as e:
        logging.error(f"获取文件信息失败 {file_path}: {str(e)}")
        return None


def copy_file(source_path, dest_path, overwrite=True):
    """
    复制文件，支持覆盖选项
    
    Args:
        source_path: 源文件路径
        dest_path: 目标文件路径
        overwrite: 是否覆盖已存在的文件
    
    Returns:
        bool: 复制是否成功
    """
    try:
        # 检查源文件是否存在
        if not os.path.exists(source_path):
            logging.error(f"源文件不存在: {source_path}")
            return False
        
        # 确保目标目录存在
        dest_dir = os.path.dirname(dest_path)
        if dest_dir:  # 避免空字符串
            os.makedirs(dest_dir, exist_ok=True)
        
        # 检查目标文件是否存在
        if os.path.exists(dest_path) and not overwrite:
            logging.warning(f"目标文件已存在，不覆盖: {dest_path}")
            return False
        
        # 复制文件
        shutil.copy2(source_path, dest_path)
        logging.info(f"文件复制成功: {source_path} -> {dest_path}")
        return True
    except PermissionError as e:
        logging.error(f"文件复制失败（权限不足） {source_path} -> {dest_path}: {str(e)}")
        return False
    except Exception as e:
        logging.error(f"文件复制失败 {source_path} -> {dest_path}: {str(e)}")
        return False


def delete_file(file_path):
    """
    删除文件
    
    Args:
        file_path: 文件路径
    
    Returns:
        bool: 删除是否成功
    """
    try:
        os.remove(file_path)
        logging.info(f"文件删除成功: {file_path}")
        return True
    except Exception as e:
        logging.error(f"文件删除失败 {file_path}: {str(e)}")
        return False


def delete_directory(dir_path):
    """
    删除目录
    
    Args:
        dir_path: 目录路径
    
    Returns:
        bool: 删除是否成功
    """
    try:
        shutil.rmtree(dir_path)
        logging.info(f"目录删除成功: {dir_path}")
        return True
    except Exception as e:
        logging.error(f"目录删除失败 {dir_path}: {str(e)}")
        return False


def should_ignore_file(file_path, ignore_patterns):
    """
    检查文件是否应该被忽略
    
    Args:
        file_path: 文件路径
        ignore_patterns: 忽略模式列表，如 ['*.tmp', '*.bak']
    
    Returns:
        bool: 是否忽略该文件
    """
    import fnmatch
    
    if not ignore_patterns:
        return False
    
    file_name = os.path.basename(file_path)
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(file_name, pattern):
            return True
    
    return False


def format_timestamp(timestamp=None):
    """
    格式化时间戳
    
    Args:
        timestamp: 时间戳，None则使用当前时间
    
    Returns:
        str: 格式化的时间字符串
    """
    if timestamp is None:
        timestamp = datetime.now()
    elif isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp)
    
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')


def setup_logging(log_file="log.txt"):
    """
    设置日志记录
    
    Args:
        log_file: 日志文件路径
    """
    # 创建logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # 清除已有的handler
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)
    
    # 创建文件handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # 创建控制台handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # 定义日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加handler
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def parse_ignore_patterns(patterns_str):
    """
    解析忽略模式字符串
    
    Args:
        patterns_str: 模式字符串，如 "*.tmp, *.bak"
    
    Returns:
        list: 模式列表
    """
    if not patterns_str:
        return []
    
    # 分割并去除空白字符
    patterns = [p.strip() for p in patterns_str.split(',')]
    # 过滤空字符串
    return [p for p in patterns if p]


def compare_files(file1, file2):
    """
    比较两个文件是否相同
    首先比较文件大小，不同则直接返回False
    相同则计算哈希值进行确认
    
    Args:
        file1: 文件1路径
        file2: 文件2路径
    
    Returns:
        bool: 文件是否相同
    """
    try:
        # 获取文件信息
        info1 = get_file_info(file1)
        info2 = get_file_info(file2)
        
        if not info1 or not info2:
            return False
        
        # 首先比较大小（优化：不比较修改时间，因为可能会误判）
        if info1['size'] != info2['size']:
            return False
        
        # 如果大小相同，计算哈希值进行确认
        hash1 = get_file_hash(file1)
        hash2 = get_file_hash(file2)
        
        if hash1 is None or hash2 is None:
            return False
        
        return hash1 == hash2
    except Exception as e:
        logging.error(f"文件比较失败 {file1} 和 {file2}: {str(e)}")
        return False