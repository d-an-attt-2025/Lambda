\# Lambda Analysis – Amazon Bedrock Security Analyzer



\## Mục đích

Lambda này thực hiện phân tích sự kiện an ninh được kích hoạt từ CloudWatch Alarm.  

Nó sử dụng Amazon Bedrock để đánh giá mức độ nghiêm trọng và phân loại hành vi tấn công dựa trên log đầu vào.



\## Luồng hoạt động

1\. CloudWatch Alarm (CPU, Rate-based, v.v.) 

2. Lambda:

&nbsp;  - Chuẩn hóa dữ liệu sự kiện

&nbsp;  - Gửi prompt sang Amazon Bedrock

&nbsp;  - Nhận kết quả phân tích (JSON)

3\. Kết quả được:

&nbsp;  - Ghi vào DynamoDB

&nbsp;  - Chuyển tiếp cho Lambda xử lý tiếp theo (Block)



\## Phân loại kết quả

Dựa trên output của Bedrock, sự kiện được phân thành:

\- \*\*SUSPICIOUS\*\*: Có dấu hiệu bất thường

\- \*\*ATTACK\*\*: Hành vi tấn công rõ ràng (DoS, scan, brute force)



\## Công nghệ sử dụng

\- AWS Lambda

\- Amazon DynamoDB

\- Amazon CloudWatch 

\- Amazon Bedrock



\## Đầu vào

\- Sự kiện từ CloudWatch Alarm (JSON)



\## Đầu ra

\- Kết quả phân tích có cấu trúc (JSON)

\- Bản ghi sự cố trong DynamoDB



\## Vai trò trong kiến trúc

Đóng vai trò \*\*bộ não phân tích thông minh\*\*, giúp hệ thống phản ứng linh hoạt thay vì rule-based thuần túy.



