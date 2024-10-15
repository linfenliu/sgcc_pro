import asyncio
import datetime
import random


def uuid(e, c, n):
    t = list("0123456789")
    t = (
        list("0123456789")
        if n == 1
        else list("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    )
    s = []
    if c is None:
        c = len(t)
    if e:
        for a in range(e):
            s.append(t[int(random.random() * c)])
    else:
        for a in range(36):
            if a == 8 or a == 13 or a == 18 or a == 23:
                s.append("-")
            elif a == 14:
                s.append("4")
            else:
                if not s[a]:
                    e = int(16 * random.random())
                    s[a] = t[3 & e | 8] if a == 19 else t[e]
    return "".join(s)


def getYesterday():
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    return yesterday.strftime("%Y-%m-%d")


def getThisMonth_Yesterday():
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    first_day_of_month = datetime.date.today().replace(day=1)
    return [first_day_of_month.strftime("%Y-%m-%d"), yesterday.strftime("%Y-%m-%d")]


def getLastMonth():
    today = datetime.date.today()
    last_day_of_last_month = today.replace(day=1) - datetime.timedelta(days=1)
    first_day_of_last_month = last_day_of_last_month.replace(day=1)
    return [
        first_day_of_last_month.strftime("%Y-%m-%d"),
        last_day_of_last_month.strftime("%Y-%m-%d"),
    ]


def getThisYear():
    today = datetime.date.today()
    return today.year


def getLastYear():
    today = datetime.date.today()
    return today.year - 1


async def getstatusoutput(cmd):
    process = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    status = process.returncode

    return (
        status,
        stdout.decode("utf-8").replace("\n", ""),
        stderr.decode("utf-8").replace("\n", ""),
    )
