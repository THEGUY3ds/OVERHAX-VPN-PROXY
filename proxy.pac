alert("hello worrld");

function FindProxyForURL (url, ghost)
{
	
	var host = ghost.toLowerCase();

        // Determine offload condition
        var setoffload = "true";

        for(var j=0; j<notoffloadlist.length; ++j)
        {
           var notoffloaddomain = notoffloadlist[j];
           if ( shExpMatch(host, notoffloaddomain) )
           {
              setoffload = "false";
           }
        }


        // Proxy traffic offload
        if (setoffload == "true")
        {
           for(var i=0; i<domainlist.length; ++i)
           {
              var value = domainlist[i];
              if ( shExpMatch(host, value) )
              {
                 return "PROXY 50.203.239.30:80";
              }
           }
        }



	// Go Direct for NetBios and localhosts
	if (isPlainHostName(host) ||
		localHostOrDomainIs(host, "localhost") ||
		localHostOrDomainIs(host, "127.0.0.1"))
	return "DIRECT";



	// Send all other request at Proxy
	return "PROXY 50.203.239.30:80";
}
