# Baseline — checkpoint 1

1. Baseline chưa gắn `agent_id`/`run_id` hay danh tính người dùng vào lần chạy: `_naive_loop` chỉ nhận `message` và `llm`, rồi đọc tài liệu (agent/loop.py:27–31). CLI có cờ chọn principal mô phỏng, nhưng baseline không truyền principal vào hàm này (agent/loop.py:83–91).
2. Trước `http_post` không có policy kiểm mục đích, quyền hay loại dữ liệu; code lấy chỉ thị do LLM phát hiện, đọc các customer ID trong đó rồi tự gọi POST (agent/loop.py:34–44). Trong baseline, luồng `_naive_loop` thực sự quyết định gửi.
3. Body được tạo ngay trong lời gọi `{"records": collected}` (agent/loop.py:44), rồi `http_post` gửi nó bằng `requests.post(..., json=body, ...)` (agent/tools.py:84). Sink ghi body đã nhận vào `reports/sink.log` (sink/sink.py:45–47).
