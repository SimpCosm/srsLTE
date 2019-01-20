0. 基于当前的UeGate模式打通4G和2G之间的电话
1. 现在UeGate和VirtualUe是以两个进程的形式运行的，其中UE的地址还是写在配置文件中的，这个肯定不行。
- 以后要把UeGate集成到Ue的GW里面中
2. 现在用它自带的Thread感觉有点难受，之后要把这个Thread改成C++自己的Thread
3. 代码中大量使用pthread，感觉还是有点难受
4. 现在的Virtual UE只支持一个UE实例，这个不行，以后得改成多个，关于UE的信息从数据库里面读，而不是从配置文件中读写

