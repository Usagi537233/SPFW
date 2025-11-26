#!/bin/bash
set -e

INSTALL_DIR="/root/spfw"
SERVICE_FILE="/lib/systemd/system/spfw.service"

echo "[EN] Creating directory: $INSTALL_DIR"
echo "[CN] 创建目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[EN] Fetching latest SPFW release info..."
echo "[CN] 获取最新 SPFW Release 信息..."
API_JSON=$(curl -s https://api.github.com/repos/Usagi537233/SPFW/releases/latest)

echo "[EN] Selecting asset exactly named 'spfw'..."
echo "[CN] 精确匹配名字为 'spfw' 的 Linux 可执行文件..."

# 精确匹配 name == "spfw"
DOWNLOAD_URL=$(echo "$API_JSON" \
    | jq -r '.assets[] | select(.name == "spfw") | .browser_download_url')

if [[ -z "$DOWNLOAD_URL" || "$DOWNLOAD_URL" == "null" ]]; then
    echo "[EN] ERROR: No asset named 'spfw' found."
    echo "[CN] 错误：未找到名为 'spfw' 的文件。"
    exit 1
fi

echo "[EN] Downloading SPFW: $DOWNLOAD_URL"
echo "[CN] 正在下载 SPFW: $DOWNLOAD_URL"
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
