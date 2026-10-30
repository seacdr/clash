#!/bin/sh
# 每小时执行    0 * * * * sh /etc/sing-box/scripts/run_cron_ax6.sh
# 每X执行       0 7,13,19 * * * sh /etc/sing-box/scripts/run_cron_ax6.sh

# alvin 订阅任务
python3 /etc/sing-box/scripts/alvin.py

# PassWall2 订阅任务
python3 /etc/sing-box/scripts/pipeline_ax6.py run --stage all

# PassWall2 更新任务
lua /usr/share/passwall2/subscribe.lua start all

