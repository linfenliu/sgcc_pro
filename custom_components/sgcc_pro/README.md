安装opencv库

pip install -i https://pypi.tuna.tsinghua.edu.cn/simple opencv-python pillow

或

进入ha终端，执行
sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
apk add py3-opencv
apk add py3-pip
apk add py3-pillow