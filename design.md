## filebrowser restful api设计

| method   | path                                                                                                                                   | Usage             |
|----------|----------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| GET      | `/api/login`                                                                                                                           | 登录                |
| POST     | `/api/logout`                                                                                                                          | 登出                |
| GET      | `/api/resources`                                                                                                                       | 获取根目录文件列表         |
| GET      | `/api/resources/{path}`                                                                                                                | 获取指定文件内容          |
| GET      | `/api/resources/{path}/`                                                                                                               | 获取指定目录文件列表        |
| PUT      | `/api/resources/{[path]/[file_name]}`                                                                                                  | 修改文件内容            |
| PATCH    | `/api/resources/{[path]/[dir_name]}?action={copy\|\|rename}&destination={{new_path}/{dir_name}}&override={true\|\|false}&rename=false` | 复制或者移动文件夹         |
| DELETE   | `/api/resources/{[path]/[file_name]}`                                                                                                  | 删除文件              |
| DELETE   | `/api/resources/{path}/`                                                                                                               | 删除文件夹             |
| POST     | `/api/resources/{[path]/[file_name]}?override={true\|\|false}`                                                                         | 新建文件              |
| POST     | `/api/resources/{{path}/{dir_name}}/?override={true\|\|false}`                                                                         | 新建文件夹             |
| GET      | `/api/raw/{[path]/[file_name]}?`                                                                                                       | 获取单个文件            |
| GET      | `/api/raw/{path}/?algo=zip&`                                                                                                           | 以zip形式下载单个文件夹     |
| GET      | `/api/raw/?files=/{path_1}/,/{file_1},/{path_2}/&algo=zip&`                                                                            | 以zip形式获取多个文件或者文件夹 |
| GET      | `/api/raw/{[path]/[file_name]}?inline=true`                                                                                            | 在线看视频             |
| POST     | `/api/tus/{[path]/[file_name]}?override={false\|\|true}`                                                                               | 创建文件上传任务          |                                                                                
| PATCH    | `/api/tus/{[path]/[file_name]}`                                                                                                        | 上传数据块             |
| HEAD/GET | `/api/tus/{[path]/[file_name]}`                                                                                                        | 查询文件上传进度          |
| DELETE   | `/api/tus/{[path]/[file_name]}`                                                                                                        | 删除文件上传任务          |
| GET      | `/api/usage`                                                                                                                           | 获取磁盘占用            |
| GET      | `/api/settings`                                                                                                                        | 获取设置              |
| PUT      | `/api/settings`                                                                                                                        | 修改设置              |
| GET      | `/api/preview/{thumb\|\|big}/{[path]/[file_name]}?inline=true&key={1773996671627?????}`                                                | 获取略缩图             |

##    

| GET | `/api/users`  | 获取用户列表 |

##

http://192.168.5.5:5173/api/raw/?files=/test/,/users/,/version/,/www/&algo=zip&
http://192.168.5.5:5173/api/raw/test/?algo=zip&
http://192.168.5.5:5173/api/raw/?files=/img/testdata/,/img/service.go,/img/service_enum.go,/img/service_test.go&algo=zip&
