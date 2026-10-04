# ---- 构建阶段 ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# 先只拷依赖清单，利用层缓存：依赖没变时不会重复下载
COPY go.mod go.sum ./
RUN go mod download

# 再拷源码（.dockerignore 已排除 config.json 等敏感文件）
COPY . .

# CGO_ENABLED=0 生成纯静态二进制，不依赖 glibc/musl，可跑在 alpine 甚至 scratch 上
# -trimpath 去掉构建机绝对路径；-s -w 去掉符号表和调试信息以减小体积
RUN CGO_ENABLED=0 GOOS=linux \
    go build -buildvcs=false -trimpath -ldflags "-s -w" -o /out/singsub .

# ---- 运行阶段 ----
FROM alpine:3.23

# ca-certificates：singsub 要用 HTTPS 抓远程订阅，缺了会报 x509 错误
# tzdata：让日志时间戳能按本地时区显示（配合 TZ 环境变量）
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 1000 singsub \
    && adduser -S -u 1000 -G singsub -H -h /app singsub

COPY --from=builder /out/singsub /usr/local/bin/singsub

# 配置、节点文件、脚本一律通过挂载卷提供，不打进镜像
# （config.json 含 token 和订阅凭据，固化进镜像会泄漏）
#   /app/config.json  ← 主配置
#   /app/node/        ← 本地订阅节点文件
#   /app/script/      ← JS 脚本
RUN mkdir -p /app/node /app/script && chown -R singsub:singsub /app

WORKDIR /app

USER singsub

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1

ENTRYPOINT ["singsub"]
CMD ["--config", "/app/config.json", "--host", "0.0.0.0", "--port", "8080"]