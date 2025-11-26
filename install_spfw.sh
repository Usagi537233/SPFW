#!/bin/bash

set -e

INSTALL_DIR="/root/spfw"
SERVICE_FILE="/lib/systemd/system/spfw.service"

echo ">>> Creating directory: $INSTALL_DIR"
echo ">>> 创建目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo ">>> Fetching latest SPFW download URL..."
echo ">>> 获取最新 SPFW 下载链接..."
LATEST_URL=$(curl -s https://api.github.com/repos/Usagi537233/SPFW/releases/latest \
  | grep "browser_download_url" \
  | grep -v ".sha256" \
  | cut -d '"' -f 4)

if [[ -z "$LATEST_URL" ]]; then
    echo ">>> Failed to get latest release link."
    echo ">>> 无法获取最新 release 下载链接。"
    exit 1
fi

echo ">>> Downloading SPFW: $LATEST_URL"
echo ">>> 正在下载 SPFW: $LATEST_URL"
wget -q "$LATEST_URL" -O spfw
chmod +x spfw

echo ">>> Creating start.sh"
echo ">>> 创建 start.sh"
cat > start.sh <<'EOF'
#!/bin/bash
nohup ./spfw -C config.json > /dev/null 2>&1 &
EOF
chmod +x start.sh

echo ">>> Creating systemd service: $SERVICE_FILE"
echo ">>> 创建 systemd 服务: $SERVICE_FILE"
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

echo ">>> Reloading systemd"
echo ">>> 重载 systemd"
systemctl daemon-reload

echo ">>> Enabling spfw.service on boot"
echo ">>> 设置 spfw.service 开机启动"
systemctl enable spfw.service

echo ">>> Starting spfw.service"
echo ">>> 启动 spfw.service"
systemctl start spfw.service

echo ">>> SPFW installation completed!"
echo ">>> SPFW 安装完成！"
