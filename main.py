#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主程序入口
文件夹管理工具（Myfile）
"""

# 最早期初始化日志，不依赖其他模块
import sys
import os
import logging
from logging.handlers import RotatingFileHandler

# 非常早期的日志设置，不依赖utils模块
def early_setup_logging():
    """在导入其他模块前设置基本日志"""
    # 使用当前工作目录（用户运行程序的目录）作为日志目录
    # 这样用户可以在运行程序的地方找到日志文件
    log_dir = os.getcwd()
    log_file = os.path.join(log_dir, "log.txt")
    
    # 创建处理器列表
    handlers = [
        RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3)
    ]
    
    # 只在标准输出可用时添加StreamHandler
    # 在windowed模式下，sys.stdout可能为None
    if sys.stdout is not None:
        handlers.append(logging.StreamHandler(sys.stdout))
    else:
        # 在windowed模式下创建一个null处理器避免错误
        handlers.append(logging.NullHandler())
    
    # 配置基本日志
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    logging.info("早期日志系统初始化成功")
    logging.info(f"当前工作目录: {log_dir}")
    logging.info(f"程序文件目录: {os.path.dirname(os.path.abspath(__file__))}")
    logging.info(f"Python版本: {sys.version}")
    logging.info(f"操作系统: {sys.platform}")
    logging.info(f"日志处理器数量: {len(handlers)}")
    logging.info(f"标准输出可用状态: {sys.stdout is not None}")

# 立即设置早期日志
early_setup_logging()

# 添加当前目录到Python路径，确保可以导入自定义模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

logging.info("准备导入应用模块")
try:
    # 导入必要的模块
    from sync_engine import SyncEngine
    from ui_main import SyncApp
    logging.info("成功导入所有必要模块")
except ImportError as e:
    logging.error(f"导入模块失败: {str(e)}", exc_info=True)
    raise


def handle_exception(exc_type, exc_value, exc_traceback):
    """全局异常处理函数"""
    import traceback
    error_msg = f"程序发生未处理的异常:\n\n{''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))}"
    logging.error(f"未处理的异常: {error_msg}")
    
    try:
        from ui_main import PYQT_AVAILABLE
        if PYQT_AVAILABLE:
            from PyQt6.QtWidgets import QMessageBox
            from PyQt6.QtCore import QApplication
            app = QApplication.instance()
            if app:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Critical)
                msg.setWindowTitle("程序发生错误")
                msg.setText(error_msg)
                msg.exec()
        else:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("程序发生错误", error_msg)
            root.destroy()
    except Exception:
        pass
    
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def main():
    """
    主函数
    初始化日志、创建同步引擎和应用界面
    """
    sys.excepthook = handle_exception
    
    print("[DEBUG] 启动文件夹管理工具（Myfile）")
    logging.info("启动文件夹管理工具（Myfile）")
    
    try:
        # 日志系统已经在程序开始时初始化
        print("[DEBUG] 开始创建应用组件")
        logging.info("开始创建应用组件")
        
        # 创建同步引擎
        print("[DEBUG] 正在创建SyncEngine...")
        logging.info("正在创建SyncEngine...")
        sync_engine = SyncEngine()
        print("[DEBUG] SyncEngine创建成功")
        
        # 创建应用界面
        print("[DEBUG] 正在创建SyncApp...")
        logging.info("正在创建SyncApp...")
        app = SyncApp()
        print("[DEBUG] SyncApp创建成功")
        logging.info("SyncApp创建成功")
        
        # 设置同步引擎到应用
        print("[DEBUG] 正在设置同步引擎...")
        logging.info("正在设置同步引擎...")
        app.set_sync_engine(sync_engine)
        print("[DEBUG] 同步引擎设置成功")
        logging.info("同步引擎设置成功")
        
        # 运行应用
        print("[DEBUG] 即将调用app.run()")
        logging.info("即将调用app.run()")
        try:
            exit_code = app.run()
            print(f"[DEBUG] app.run() returned with code: {exit_code}")
            sys.stdout.flush()
            logging.info(f"app.run()返回代码: {exit_code}")
        except Exception as e:
            error_msg = f"app.run()执行出错: {str(e)}"
            print("[DEBUG] " + error_msg)
            sys.stdout.flush()
            logging.error(error_msg, exc_info=True)
            exit_code = 1
        
        # 清理日志处理器
        for handler in logging.root.handlers[:]:
            try:
                handler.flush()
                handler.close()
            except Exception:
                pass
        
        # 只有在GUI正常退出后才记录"程序正常退出"
        logging.info("程序正常退出")
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        logging.info("用户中断程序")
        sys.exit(0)
    except ImportError as e:
        error_msg = f"缺少必要的模块: {str(e)}"
        logging.error(error_msg, exc_info=True)
        print(error_msg)
        print("请安装依赖: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logging.error(f"程序运行出错: {str(e)}", exc_info=True)
        print(f"错误: {str(e)}")
        # 如果没有GUI，显示错误信息
        try:
            from ui_main import PYQT_AVAILABLE
            if not PYQT_AVAILABLE:
                import tkinter as tk
                from tkinter import messagebox
                root = tk.Tk()
                root.withdraw()  # 隐藏主窗口
                messagebox.showerror("错误", f"程序运行出错: {str(e)}")
                root.destroy()
        except Exception:
            pass
        sys.exit(1)
    



if __name__ == "__main__":
    # 确保中文正常显示
    # 在Windows上，控制台编码可能需要设置
    if sys.platform.startswith('win'):
        try:
            # 设置Windows控制台编码为UTF-8
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception as e:
            logging.error(f"设置控制台编码出错: {e}")
            # 即使设置失败也继续执行
    
    # 记录程序启动信息
    logging.info("程序开始启动...")
    
    # 启动主程序
    main()