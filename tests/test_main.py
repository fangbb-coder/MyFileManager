#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单元测试模块
用于文件夹管理工具（Myfile）
"""

import unittest
import os
import tempfile
import shutil
from datetime import datetime

from utils import (
    get_file_hash, get_file_info, copy_file, delete_file, 
    delete_directory, should_ignore_file, format_timestamp, 
    parse_ignore_patterns, compare_files
)
from config_manager import ConfigManager


class TestUtils(unittest.TestCase):
    """测试工具函数"""

    def setUp(self):
        """设置测试环境"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, 'w', encoding='utf-8') as f:
            f.write("test content")

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_get_file_hash(self):
        """测试获取文件哈希值"""
        hash1 = get_file_hash(self.test_file)
        hash2 = get_file_hash(self.test_file)
        self.assertIsNotNone(hash1)
        self.assertEqual(hash1, hash2)

    def test_get_file_info(self):
        """测试获取文件信息"""
        info = get_file_info(self.test_file)
        self.assertIsNotNone(info)
        self.assertEqual(info['name'], 'test.txt')
        self.assertEqual(info['size'], 12)
        self.assertIn('mtime', info)
        self.assertIn('path', info)

    def test_copy_file(self):
        """测试复制文件"""
        dest_file = os.path.join(self.test_dir, "copy.txt")
        result = copy_file(self.test_file, dest_file)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(dest_file))
        with open(dest_file, 'r', encoding='utf-8') as f:
            self.assertEqual(f.read(), "test content")

    def test_delete_file(self):
        """测试删除文件"""
        result = delete_file(self.test_file)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_file))

    def test_delete_directory(self):
        """测试删除目录"""
        test_subdir = os.path.join(self.test_dir, "subdir")
        os.makedirs(test_subdir)
        result = delete_directory(test_subdir)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(test_subdir))

    def test_should_ignore_file(self):
        """测试文件忽略判断"""
        patterns = ['*.tmp', '*.bak', '*.log']
        self.assertTrue(should_ignore_file('test.tmp', patterns))
        self.assertTrue(should_ignore_file('test.bak', patterns))
        self.assertFalse(should_ignore_file('test.txt', patterns))

    def test_format_timestamp(self):
        """测试时间戳格式化"""
        timestamp = 1609459200.0
        formatted = format_timestamp(timestamp)
        self.assertIsInstance(formatted, str)

    def test_parse_ignore_patterns(self):
        """测试解析忽略模式"""
        patterns_str = "*.tmp, *.bak, *.log"
        patterns = parse_ignore_patterns(patterns_str)
        self.assertEqual(len(patterns), 3)
        self.assertIn('*.tmp', patterns)

    def test_compare_files(self):
        """测试文件比较"""
        test_file2 = os.path.join(self.test_dir, "test2.txt")
        with open(test_file2, 'w', encoding='utf-8') as f:
            f.write("test content")
        
        result = compare_files(self.test_file, test_file2)
        self.assertTrue(result)
        
        with open(test_file2, 'w', encoding='utf-8') as f:
            f.write("different content")
        
        result = compare_files(self.test_file, test_file2)
        self.assertFalse(result)


class TestConfigManager(unittest.TestCase):
    """测试配置管理器"""

    def setUp(self):
        """设置测试环境"""
        self.test_config_file = os.path.join(tempfile.mkdtemp(), "test_config.json")
        self.config = ConfigManager(self.test_config_file)

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)

    def test_get_default_config(self):
        """测试获取默认配置"""
        width = self.config.get("window_width")
        self.assertEqual(width, 1200)

    def test_set_and_get_config(self):
        """测试设置和获取配置"""
        self.config.set("window_width", 1920)
        width = self.config.get("window_width")
        self.assertEqual(width, 1920)

    def test_save_and_load_config(self):
        """测试保存和加载配置"""
        self.config.set("window_width", 1920)
        new_config = ConfigManager(self.test_config_file)
        width = new_config.get("window_width")
        self.assertEqual(width, 1920)

    def test_ignore_patterns(self):
        """测试忽略模式"""
        patterns = self.config.get_ignore_patterns()
        self.assertIsInstance(patterns, list)
        
        self.config.set_ignore_patterns(['*.tmp', '*.bak'])
        patterns = self.config.get_ignore_patterns()
        self.assertIn('*.tmp', patterns)
        self.assertIn('*.bak', patterns)

    def test_window_size(self):
        """测试窗口大小"""
        width, height = self.config.get_window_size()
        self.assertEqual(width, 1200)
        self.assertEqual(height, 800)
        
        self.config.set_window_size(1920, 1080)
        width, height = self.config.get_window_size()
        self.assertEqual(width, 1920)
        self.assertEqual(height, 1080)

    def test_last_folder(self):
        """测试最后使用的文件夹"""
        path = "/path/to/folder"
        self.config.set_last_folder("a", path)
        result = self.config.get_last_folder("a")
        self.assertEqual(result, path)

    def test_reset_to_default(self):
        """测试重置为默认配置"""
        self.config.set("window_width", 1920)
        self.config.reset_to_default()
        width = self.config.get("window_width")
        self.assertEqual(width, 1200)


class TestSyncEngine(unittest.TestCase):
    """测试同步引擎"""

    def setUp(self):
        """设置测试环境"""
        from sync_engine import SyncEngine
        self.test_dir_a = tempfile.mkdtemp()
        self.test_dir_b = tempfile.mkdtemp()
        self.sync_engine = SyncEngine()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.test_dir_a):
            shutil.rmtree(self.test_dir_a)
        if os.path.exists(self.test_dir_b):
            shutil.rmtree(self.test_dir_b)

    def test_sync_engine_initialization(self):
        """测试同步引擎初始化"""
        self.assertIsNotNone(self.sync_engine)
        self.assertFalse(self.sync_engine._stop_requested)
        self.assertFalse(self.sync_engine._pause_requested)

    def test_stop_sync(self):
        """测试停止同步"""
        self.sync_engine.stop()
        self.assertTrue(self.sync_engine._stop_requested)

    def test_pause_sync(self):
        """测试暂停同步"""
        self.sync_engine.pause()
        self.assertTrue(self.sync_engine._pause_requested)

    def test_get_progress(self):
        """测试获取进度"""
        progress = self.sync_engine.get_progress()
        self.assertIsInstance(progress, int)
        self.assertGreaterEqual(progress, 0)
        self.assertLessEqual(progress, 100)

    def test_get_log(self):
        """测试获取日志"""
        logs = self.sync_engine.get_log()
        self.assertIsInstance(logs, list)


if __name__ == '__main__':
    unittest.main()
