global numberofua :table[addr] of int = table();
global useragent1:table[addr] of string =table();
global useragent2:table[addr] of string =table();
global useragent3:table[addr] of string =table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
	local sourceID=c$id$orig_h;
	local useagent : string;
	local exist=c$http?$user_agent;
	if(exist)
	{
		useagent=c$http$user_agent;
		if((sourceID in useragent1)&&(sourceID in useragent2)&&(sourceID in useragent3))
		{
			;
		}
		else if((sourceID in useragent1)&&(sourceID in useragent2))
		{
			if((useragent1[sourceID]!=useagent)&&(useragent2[sourceID]!=useagent))
			{
				useragent3[sourceID]=useagent;
			}
		}
		else if(sourceID in useragent1)
		{
			if(useragent1[sourceID]!=useagent)
			{
				useragent2[sourceID]=useagent;
			}
		}
		else
		{
			useragent1[sourceID]=useagent;
		}
	}
}
event zeek_done()
{
	for(a in useragent3)
		print fmt("%s is a proxy",a);
}
