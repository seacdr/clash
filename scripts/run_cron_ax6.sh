#!/bin/sh

# 每小时执行 0 * * * * sh /etc/sing-box/scripts/run_cron_ax6.sh

# PassWall2 订阅任务
python3 /etc/sing-box/scripts/pipeline_ax6.py run --stage all

# PassWall2 更新任务
lua /usr/share/passwall2/subscribe.lua start all

