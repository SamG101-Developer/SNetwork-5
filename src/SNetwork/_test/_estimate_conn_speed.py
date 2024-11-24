import psutil, time, requests


def estimate_intra_network_speed(interval: int = 5) -> tuple[int, int]:
    net_io_start = psutil.net_io_counters()
    bytes_sent_start = net_io_start.bytes_sent
    bytes_recv_start = net_io_start.bytes_recv
    time.sleep(interval)

    net_io_end = psutil.net_io_counters()
    bytes_sent_end = net_io_end.bytes_sent
    bytes_recv_end = net_io_end.bytes_recv

    send_speed = (bytes_sent_end - bytes_sent_start) // interval
    recv_speed = (bytes_recv_end - bytes_recv_start) // interval
    return send_speed * 8, recv_speed * 8


if __name__ == "__main__":
    s, r = estimate_intra_network_speed()
    print(f"Send Speed: {s} bps\nReceive Speed: {r} bps")
