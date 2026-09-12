import os
import time
import hmac
import hashlib
import base64
import struct
import threading
from io import BytesIO
from urllib.parse import quote

import qrcode
from flask import Flask, jsonify, send_file


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# Срок действия одного общего credential.
#
# Например:
#
# ACCESS_TTL_MINUTES=10
#
# означает 10 минут.
# ------------------------------------------------------------

ACCESS_TTL_MINUTES = int(
    os.environ["ACCESS_TTL_MINUTES"]
)

ACCESS_TTL_SECONDS = (
    ACCESS_TTL_MINUTES * 60
)


# ------------------------------------------------------------
# Имя пользователя dumbproxy.
#
# Это публичное значение.
# Его увидит пользователь.
# ------------------------------------------------------------

PROXY_USERNAME = os.environ[
    "PROXY_USERNAME"
]


# ------------------------------------------------------------
# Публичный адрес dumbproxy.
#
# ВАЖНО:
# это НЕ имя Docker-контейнера.
#
# Например:
#
# PROXY_HOST=proxy.example.com
#
# или:
#
# PROXY_HOST=1.2.3.4
# ------------------------------------------------------------

PROXY_HOST = os.environ[
    "PROXY_HOST"
]


# ------------------------------------------------------------
# Публичный порт proxy.
# ------------------------------------------------------------

PROXY_PORT = int(
    os.environ["PROXY_PORT"]
)


# ------------------------------------------------------------
# Схема proxy.
#
# Для обычного HTTP proxy:
#
#   http
#
# ------------------------------------------------------------

PROXY_SCHEME = os.environ.get(
    "PROXY_SCHEME",
    "http"
)


# ------------------------------------------------------------
# HMAC secret.
#
# Этот secret должен совпадать с secret,
# который использует dumbproxy.
#
# Храним его в .env в HEX-виде.
# ------------------------------------------------------------

HMAC_SECRET_HEX = os.environ[
    "DUMBPROXY_HMAC_SECRET"
]


try:

    HMAC_SECRET = bytes.fromhex(
        HMAC_SECRET_HEX
    )

except ValueError as exc:

    raise RuntimeError(
        "DUMBPROXY_HMAC_SECRET "
        "must contain HEX characters"
    ) from exc


# ============================================================
# RUNTIME STATE
# ============================================================

# ------------------------------------------------------------
# Здесь хранится текущий общий credential.
#
# Нам НЕ нужна база данных:
#
#   credential один;
#   он общий для всех;
#   срок его жизни небольшой.
#
# После перезапуска контейнера будет создан новый.
# ------------------------------------------------------------

current_credential = None


# ------------------------------------------------------------
# Защищаем создание credential от одновременных запросов.
#
# Например, если 20 человек одновременно открыли сайт,
# они не должны получить 20 разных credential.
# ------------------------------------------------------------

credential_lock = threading.Lock()


# ============================================================
# HMAC
# ============================================================

def generate_hmac_password(
    username: str,
    expires_at: int
) -> str:

    """
    Создаёт временный HMAC credential.

    Timestamp включается в подписываемые данные,
    поэтому credential автоматически становится
    недействительным после истечения времени.

    Результат кодируется URL-safe Base64.
    """

    # Unix timestamp в формате uint64 big-endian.
    timestamp_bytes = struct.pack(
        ">Q",
        expires_at
    )


    # Данные для подписи.
    #
    # Формат должен соответствовать HMAC-схеме
    # используемой dumbproxy.
    message = (
        b"dumbproxy grant token v1"
        + username.encode("utf-8")
        + timestamp_bytes
    )


    # Создаём HMAC-SHA256.
    signature = hmac.new(
        HMAC_SECRET,
        message,
        hashlib.sha256
    ).digest()


    # В token помещаем timestamp + подпись.
    token = (
        timestamp_bytes
        + signature
    )


    # URL-safe Base64.
    #
    # "=" в конце убираем.
    return base64.urlsafe_b64encode(
        token
    ).rstrip(b"=").decode("ascii")


# ============================================================
# CREDENTIAL MANAGEMENT
# ============================================================

def create_credential():

    """
    Создаёт новый общий credential.
    """

    global current_credential


    # Когда credential перестанет действовать.
    expires_at = int(
        time.time()
        + ACCESS_TTL_SECONDS
    )


    # Генерируем HMAC password.
    password = generate_hmac_password(
        PROXY_USERNAME,
        expires_at
    )


    current_credential = {

        "username":
            PROXY_USERNAME,

        "password":
            password,

        "expires_at":
            expires_at,
    }


    return current_credential


def get_current_credential():

    """
    Возвращает текущий credential.

    Если credential отсутствует
    или уже истёк — создаётся новый.

    Таким образом:

        посетитель №1
              ↓
        создаётся credential A

        посетитель №2
              ↓
        получает credential A

        посетитель №3
              ↓
        получает credential A

        ...

        10 минут прошло

        посетитель №N
              ↓
        создаётся credential B
    """

    global current_credential


    with credential_lock:

        now = int(
            time.time()
        )


        if (
            current_credential is None
            or now >=
               current_credential["expires_at"]
        ):

            return create_credential()


        return current_credential


# ============================================================
# PROXY URL
# ============================================================

def build_proxy_url(
    credential
):

    """
    Формирует готовый URL подключения к proxy.

    Пример:

        http://user:password@example.com:8080
    """

    username = quote(
        credential["username"],
        safe=""
    )


    password = quote(
        credential["password"],
        safe=""
    )


    return (
        f"{PROXY_SCHEME}://"
        f"{username}:"
        f"{password}@"
        f"{PROXY_HOST}:"
        f"{PROXY_PORT}"
    )


# ============================================================
# WEB ROUTES
# ============================================================

@app.route("/")
def index():

    """
    Отдаём HTML из внешнего volume.
    """

    return send_file(
        "/app/site/index.html"
    )


@app.route("/api/access")
def api_access():

    """
    API текущего общего доступа.
    """

    credential = (
        get_current_credential()
    )


    expires_in = max(
        0,
        credential["expires_at"]
        - int(time.time())
    )


    proxy_url = (
        build_proxy_url(
            credential
        )
    )


    return jsonify({

        "username":
            credential["username"],

        "password":
            credential["password"],

        "proxy_host":
            PROXY_HOST,

        "proxy_port":
            PROXY_PORT,

        "proxy_scheme":
            PROXY_SCHEME,

        "proxy_url":
            proxy_url,

        "expires_in":
            expires_in,
    })


@app.route("/api/qr")
def api_qr():

    """
    Генерирует QR-код с готовым proxy URL.
    """

    credential = (
        get_current_credential()
    )


    proxy_url = (
        build_proxy_url(
            credential
        )
    )


    # Создаём QR.
    image = qrcode.make(
        proxy_url
    )


    output = BytesIO()


    image.save(
        output,
        format="PNG"
    )


    output.seek(0)


    return send_file(
        output,
        mimetype="image/png"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    # Порт приложения намеренно не выносим
    # в .env.
    #
    # Это внутренний технический параметр.
    app.run(
        host="0.0.0.0",
        port=3000
    )
