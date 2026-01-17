#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件管理模块
用于文件夹管理工具（Myfile）
"""

import json
import os
from typing import Dict, Any, Optional, List


class ConfigManager:
    """配置管理器类"""

    DEFAULT_CONFIG = {
        "window_width": 1200,
        "window_height": 800,
        "sync_mode": "a_to_b",
        "sync_delete": False,
        "ignore_patterns": "*.tmp,*.bak,*.log",
        "only_show_diff_files": False,
        "file_slimming_max_files": 100,
        "duplicate_hash_algo": "md5",
        "duplicate_threads": 4,
        "last_folder_a": "",
        "last_folder_b": "",
        "last_duplicate_folder": "",
        "last_file_slimming_folder": "",
        "theme": "default"
    }

    def __init__(self, config_file: str = "config.json"):
        """
        初始化配置管理器

        Args:
            config_file: 配置文件路径
        """
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        加载配置文件

        Returns:
            Dict[str, Any]: 配置字典
        """
        if not os.path.exists(self.config_file):
            return self.DEFAULT_CONFIG.copy()

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                merged_config = self.DEFAULT_CONFIG.copy()
                merged_config.update(config)
                return merged_config
        except Exception as e:
            return self.DEFAULT_CONFIG.copy()

    def save_config(self) -> bool:
        """
        保存配置文件

        Returns:
            bool: 是否保存成功
        """
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置项

        Args:
            key: 配置键
            default: 默认值

        Returns:
            Any: 配置值
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any, save: bool = True) -> bool:
        """
        设置配置项

        Args:
            key: 配置键
            value: 配置值
            save: 是否立即保存

        Returns:
            bool: 是否设置成功
        """
        try:
            self.config[key] = value
            if save:
                return self.save_config()
            return True
        except Exception:
            return False

    def get_ignore_patterns(self) -> List[str]:
        """
        获取忽略模式列表

        Returns:
            List[str]: 忽略模式列表
        """
        patterns_str = self.get("ignore_patterns", "")
        if not patterns_str:
            return []
        return [p.strip() for p in patterns_str.split(',') if p.strip()]

    def set_ignore_patterns(self, patterns: List[str], save: bool = True) -> bool:
        """
        设置忽略模式列表

        Args:
            patterns: 忽略模式列表
            save: 是否立即保存

        Returns:
            bool: 是否设置成功
        """
        patterns_str = ", ".join(patterns)
        return self.set("ignore_patterns", patterns_str, save)

    def get_window_size(self) -> tuple:
        """
        获取窗口大小

        Returns:
            tuple: (宽度, 高度)
        """
        return (self.get("window_width", 1200), self.get("window_height", 800))

    def set_window_size(self, width: int, height: int, save: bool = True) -> bool:
        """
        设置窗口大小

        Args:
            width: 宽度
            height: 高度
            save: 是否立即保存

        Returns:
            bool: 是否设置成功
        """
        self.set("window_width", width, save=False)
        return self.set("window_height", height, save)

    def get_last_folder(self, folder_type: str) -> str:
        """
        获取最后使用的文件夹路径

        Args:
            folder_type: 文件夹类型（"a", "b", "duplicate", "file_slimming"）

        Returns:
            str: 文件夹路径
        """
        key = f"last_folder_{folder_type}"
        return self.get(key, "")

    def set_last_folder(self, folder_type: str, path: str, save: bool = True) -> bool:
        """
        设置最后使用的文件夹路径

        Args:
            folder_type: 文件夹类型（"a", "b", "duplicate", "file_slimming"）
            path: 文件夹路径
            save: 是否立即保存

        Returns:
            bool: 是否设置成功
        """
        key = f"last_folder_{folder_type}"
        return self.set(key, path, save)

    def reset_to_default(self) -> bool:
        """
        重置为默认配置

        Returns:
            bool: 是否重置成功
        """
        self.config = self.DEFAULT_CONFIG.copy()
        return self.save_config()
