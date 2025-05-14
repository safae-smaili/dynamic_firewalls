# Dynamic Firewall
This project is an improvement of the project this repo:
https://github.com/afmdnf/firewall
# Improvements:
1.Combined Port and IP Rule Logic
The previous code handled ports and IPs separately:
I add the logic to handel a rule with is a combination of ports and rules 
example:
the rule ("inbound","tcp", 80, "192.168.1.3") shoudon't be accssepted 
this is the fiare wall rules in the csv file at this time:
inbound,tcp,80,192.168.1.2
outbound,tcp,10000-20000,192.168.10.11
inbound,udp,53,192.168.1.1-192.168.2.5
outbound,udp,1000-2000,52.12.48.92
inbound,tcp,443-8547,0.0.1.8-255.127.61.44
![Before adding Rule class](https://github.com/user-attachments/assets/843cd830-4bbd-443f-be3f-a1b62234683e)
After adding the Rule classe the probleme resolved:
![After the Rule classe](https://github.com/user-attachments/assets/4eb31b29-6859-47e0-8370-e15b7af28ea7)
2. Adding the automatique syncronization of the rules from csv file without the neede to relance the programme :
example:
![image](https://github.com/user-attachments/assets/143e5993-6537-486c-a90e-8fab58aa7a38)
3. dynamicly add and remove firewall rules:
add rules to csv file automaticly.
removing rules that not be uset for a long time
4. stopping DDos attacks and deleting all the rules that accepte the ip address that tray to do a DDos attack
![image](https://github.com/user-attachments/assets/305b7edf-3778-46ae-8abd-7c1bf9703709)

