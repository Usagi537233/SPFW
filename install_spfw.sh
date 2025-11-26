#!/bin/bash
set -e

INSTALL_DIR="/root/spfw"
SERVICE_FILE="/lib/systemd/system/spfw.service"

echo "[EN] Creating directory: $INSTALL_DIR"
echo "[CN] 创建目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[EN] Fetching latest SPFW release information..."
echo "[CN] 获取最新 SPFW Release 信息..."
API_JSON=$(curl -s https://api.github.com/repos/Usagi537233/SPFW/releases/latest)

echo "[EN] Selecting Linux x64 asset named 'spfw'..."
echo "[CN] 选择名字为 'spfw' 的 Linux 版本文件..."
DOWNLOAD_URL=$(echo "$API_JSON" | grep '"name": "spfw"' -n -A 3 | grep "browser_download_url" | cut -d '"' -f 4)

if [[ -z "$DOWNLOAD_URL" ]]; then
    echo "[EN] Could not find asset named 'spfw' in latest release!"
    echo "[CN] 最新 Release 中未找到名为 'spfw' 的文件！"
    exit 1
fi

echo "[EN] Downloading SPFW from: $DOWNLOAD_URL"
echo "[CN] 下载 SPFW 文件: $DOWNLOAD_URL"
curl -L "$DOWNLOAD_URL" -o spfw
chmod +x spfw

echo "[EN] Creating start.sh"
echo "[CN] 创建 start.sh"
cat > start.sh <<'EOF'
#!/bin/bash
nohup ./spfw -C config.json > /dev/null 2>&1 &
EOF
chmod +x start.sh

echo "[EN] Creating systemd service"
echo "[CN] 创建 systemd 服务"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=spfw
After=network.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/root/spfw
KillMode=control-group
Restart=no
ExecStart=/root/spfw/start.sh

[Install]
WantedBy=multi-user.target
EOF

echo "[EN] Reloading systemd"
echo "[CN] 重载 systemd"
systemctl daemon-reload

echo "[EN] Enabling spfw.service on boot"
echo "[CN] 设置 spfw.service 开机启动"
systemctl enable spfw.service

echo "[EN] Starting spfw.service"
echo "[CN] 启动 spfw.service"
systemctl start spfw.service

echo "[EN] SPFW installation completed!"
echo "[CN] SPFW 安装完成！"
