\# Lambda Detect – DoS \& Abnormal Traffic Detection



\## Mục đích

Lambda này chịu trách nhiệm quét log ứng dụng / ALB để phát hiện các IP có hành vi bất thường hoặc tấn công DoS.



\## Luồng hoạt động

1\. CloudWatch Logs Subscription Filter đẩy log vào Lambda

2\. Lambda phân tích:

&nbsp;  - IP nguồn

&nbsp;  - Tần suất request

3\. Thống kê số lần xuất hiện của mỗi IP trong cửa sổ thời gian



\## Tiêu chí phát hiện

\- CPU trên 60%

\- IP gửi số lượng request vượt ngưỡng 





\## Xử lý kết quả

\- IP nghi vấn được lưu vào DynamoDB

\- Nếu vượt ngưỡng:

  - Gửi cảnh báo (email)

&nbsp; - Có thể kích hoạt Lambda Block IP





\## Công nghệ sử dụng

\- AWS Lambda

\- Amazon CloudWatch Logs

\- Amazon DynamoDB

\- Amazon Simple Email Service



\## Đầu vào

\- Log ứng dụng từ CloudWatch Logs



\## Đầu ra

\- Danh sách IP nghi vấn

\- Thống kê định lượng phục vụ phân tích tiếp theo



\## Vai trò trong kiến trúc

Là lớp \*\*phát hiện định lượng\*\*



