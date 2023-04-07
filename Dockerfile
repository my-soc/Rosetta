FROM python:3.12.0a5-slim
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN useradd --create-home rosetta

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    if ! getent group rosetta > /dev/null 2>&1; then \
        groupadd -g ${GROUP_ID} rosetta; \
    fi && \
    usermod -u ${USER_ID} -g ${GROUP_ID} rosetta \
;fi
RUN mkdir -p /var/rosetta && chown rosetta:rosetta /var/rosetta
WORKDIR /var/rosetta
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R rosetta:rosetta /var/rosetta/backend
USER rosetta
ENV PATH="/var/rosetta/.local/bin:${PATH}"
WORKDIR /var/rosetta/backend
ENV PORT=8000
CMD sh -c "PORT=${PORT:-8000} uvicorn app.main:app --host 0.0.0.0 --port $PORT"
