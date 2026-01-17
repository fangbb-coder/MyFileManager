# GitHub 仓库创建和代码推送指南

## 1. 在GitHub网站上创建新仓库

1. 打开浏览器，访问 https://github.com 并登录您的账户
2. 点击页面右上角的 "+" 图标，选择 "New repository"
3. 在 "Repository name" 字段中输入仓库名称，例如 "MyFileManager"
4. 选择仓库可见性（公开或私有）
5. 不要勾选 "Add a README file"、"Add .gitignore" 和 "Choose a license" 选项，因为我们已经在本地创建了这些文件
6. 点击 "Create repository" 按钮

## 2. 获取仓库URL

创建仓库后，您将看到一个页面，其中包含仓库的URL。复制这个URL，通常它看起来像这样：
```
https://github.com/您的用户名/MyFileManager.git
```

## 3. 本地配置远程仓库并推送代码

请将以下步骤中的 `<您的仓库URL>` 替换为您在上一步复制的实际URL，然后执行这些命令：

```bash
# 配置远程仓库
"C:\Program Files\Git\cmd\git.exe" remote add origin <您的仓库URL>

# 推送代码到GitHub
"C:\Program Files\Git\cmd\git.exe" push -u origin master
```

如果遇到权限问题，GitHub可能会提示您输入用户名和密码。现在GitHub推荐使用个人访问令牌(PAT)代替密码。如果您需要设置个人访问令牌，请按照GitHub的提示进行操作。

完成后，您的代码将成功推送到GitHub仓库！