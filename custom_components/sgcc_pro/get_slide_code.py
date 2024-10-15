import base64
import hashlib
import json
import sys
from io import BytesIO

from PIL import Image, ImageEnhance, ImageDraw
import numpy as np
import cv2


def get_slide_code(jsonfile):
    with open(jsonfile, 'r', encoding='utf-8') as json_data:
        data = json.load(json_data)
        # print(data)
        blockY = data['blockY']
        base64_png1 = data['canvasSrc']
        base64_png2 = data['blockSrc']
        decode_png1 = base64.b64decode(base64_png1[22:])
        decode_png2 = base64.b64decode(base64_png2[22:])
        imgorgin = Image.open(BytesIO(decode_png1))
        imgblock = Image.open(BytesIO(decode_png2))
        img = imgorgin.crop((0, int(blockY) - 1, imgorgin.width, int(blockY) + imgblock.height + 1))
        img = ImageEnhance.Color(img).enhance(0.2)
        img = ImageEnhance.Contrast(img).enhance(1.5)
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, imgorgin.width - 1, imgblock.height + 1], outline=(255, 255, 255), width=1)
        img = np.array(img)  # 转化为numpy
        img = cv2.resize(img, (imgorgin.width, imgblock.height + 2))  # 用cv2resize
        img = cv2.GaussianBlur(img, (5, 5), 0)
        cv2.imwrite('.slide0.png', img)
        img = img[:, :, (2, 1, 0)]  # BGR图像转RGB
        img1 = img.copy()
        for w in range(img.shape[1]):
            cnt = 0
            for h in range(img.shape[0]):
                if img[h, w, 0] < 50 and img[h, w, 1] < 50 and img[h, w, 2] < 50:
                    for c in range(3):
                        img[h, w, c] = 0
                else:
                    cnt = cnt + 1
                    for c in range(3):
                        img[h, w, c] = 255
            if cnt >= 10:
                for h in range(img.shape[0]):
                    for c in range(3):
                        img[h, w, c] = 255

        cv2.imwrite('.slide1.png', img)
        canny_img = cv2.Canny(img, 0, 75)  # 边缘检测
        cv2.imwrite('.slide2.png', canny_img)
        counts, _ = cv2.findContours(canny_img, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)  # 轮廓检测
        result = []
        for c in counts:
            x, y, w, h = cv2.boundingRect(c)
            if w < 40:
                continue
            if h < 40:
                continue
            cv2.rectangle(img1, (x, y), (x + w, y + h), (0, 0, 255), 2)
            # print(f"左上点的坐标为：{x, y}，右下点的坐标为{x + w, y + h}")
            result.append(x)
        cv2.imwrite('.result.png', img1)
        return result[0]


if __name__ == '__main__':
    # print(sys.argv[1:])
    result = get_slide_code(sys.argv[1:][0])
    print(result)
    exit(result)