# ClearPass-Services
<BR>
###################################################################
                                                                  
The purpose of this code is to extract the ClearPass Policy        
Manager Service configuration details account.                    
This uses the legacy ClearPass XML interface - the configuration  
information is not exposed via the RESTful API as of ClearPass    
v6.9.5.                                                           <BR>
WARNING: This code has only had minimal testing on v6.9 code,     
though I will expect it to work on v6.8 and v6.7.                 <BR><BR>
                                                                  
Known Limitations<BR>                                                
Enforcement Profiles: AOS DUR using Standard forms do not work<BR>  
AOS DUR usuing Advanced seems to but not the bandwidth/QOS<BR>      
AuthSources: Only AD and RADIUS Server tested<BR>                   
Posture Compliance: Only reports the posture compliance name<BR>     
Local Users: These are currently not been processed<BR>              
<BR>                                                                 
Author: Derin Mellor<BR>                                            
Date: 21st April 2021<BR>                                             
Version: 0.2<BR>                                                    
Contact: mellor.derin@gmail.com<BR>                          
<BR>                                                                  
Changes<BR>                                                           
0.1 First version<BR>                                                 
0.2 Due to problems on macOS moved from pycurl module to requests 
     module. Significant enhancements on pdf output.<BR>              
<BR>
  
Usage: services.py -D -h hostname/IP -u username -p password<BR>    
Where:<BR>                                                          
  -D  debug<BR>                                                       
  -h  hostname/IP - note validation of certificate or IP will    
      work<BR>                                                       
  -u  username - typically use the generic apiadmin account<BR>       
<BR>                                                                  
Running Challenges<BR>                                               
The two challenging python modules that need loading at pycurl    
and lxml.<BR>                                                         
macOS:<BR>                                                       
  1) macOS defaults to python2 - this is written in python3!<BR>    
  2) It defaults to using the LibreSSL libraries whereas pycurl   
      expects openssl libraries. Search the internet for          
      ssl-backend-error-when-using-openssl<BR>                      
  3) lxml causes challenges - look at                             
      https://lxml.de/installation.html<BR>                          
<BR>                                                                 
When the code starts running it uses the XML API to extract the   
configuration information and place these into the appropriate    
objects. Once this is complete it will output the information.    
Currently all the information is output on the console.<BR>          
<BR>                                                                  
WARNING: If using on a Linux environment you might experience the 
error:<BR>                                                             
      ./services.py -h clearpass.hpearubademo.com<BR>
  
      env: python3\r: No such file or directory<BR>
<BR>  
This is most likely caused due to being developed on a Windows   
platform that within the file format uses \n\r at the end-of-line
Linux format just uses a \r. If you experience this error convert
it to a Linux format using the "dos2unix" command:<BR>              
      dos2unix services.py services.py                           
                                                                  
