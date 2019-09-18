function FindProxyForURL (url, ghost)
{
	var host = ghost.toLowerCase();


        // Domain list to offload
        var domainlist = Array (
           "*.googlevideo.com",
           "*.abc.net.au",
           "*.apple.com",
           "*.windowsupdate.com",
           "*.microsoft.com",
           "*.gvt1.com",
           "*.ggpht.com",
           "*.sharepoint.com",
//           "www.google.com",
//           "www.google.com.au",
           "nosslsearch.google.com",
           "updates-http.cdn-apple.com",
//           "clients1.google.com",
//           "clients2.google.com",
//           "clients3.google.com",
//           "clients4.google.com",
//           "clients5.google.com",
//           "clients6.google.com",
           "ssl.gstatic.com",
//           "googleads.g.doubleclick.net",
//           "stats.g.doubleclick.net",
           "www.msftconnecttest.com"
//           "ocsp.digicert.com",
//           "play.google.com",
//           "www.gstatic.com",
//           "www.google-analytics.com"
        );


        // Domain list not to offload
        var notoffloadlist = Array (
           "*.det.nsw.edu.au",
           "*.schools.nsw.edu.au",
           "*.education.nsw.gov.au",
           "guzzoni.apple.com"
        );


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
                 return "PROXY proxys.det.nsw.edu.au:8080";
              }
           }
        }

	
        // Go Direct for Citrix SSO infrastructure
        if (    dnsDomainIs (host, "access.dev.det.nsw.edu.au") ||
                dnsDomainIs (host, "access.uat.det.nsw.edu.au") ||
                dnsDomainIs (host, "access.det.nsw.edu.au") ||
                dnsDomainIs (host, "access.poc.det.nsw.edu.au") ||
                dnsDomainIs (host, "access.test.det.nsw.edu.au") ||
                ( (dnsDomainIs (host, ".uc.det.nsw.edu.au")) && ( host != "myemail.uc.det.nsw.edu.au") ) ||
                host == "oa.det.nsw.edu.au" ||
                dnsDomainIs (host, ".ssoc.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vdi.det.nsw.edu.au") ||
                dnsDomainIs (host, ".ctx.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vpx.det.nsw.edu.au") ||
                dnsDomainIs (host, ".sso.uat.det.nsw.edu.au") ||
                dnsDomainIs (host, ".ctx.uat.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vdi.uat.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vpx.uat.det.nsw.edu.au") ||
                dnsDomainIs (host, ".sso.pre.det.nsw.edu.au") ||
                dnsDomainIs (host, ".ctx.pre.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vdi.pre.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vpx.pre.det.nsw.edu.au") ||
                dnsDomainIs (host, ".sso.dev.det.nsw.edu.au") ||
                dnsDomainIs (host, ".ctx.dev.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vdi.dev.det.nsw.edu.au") ||
                dnsDomainIs (host, ".vpx.dev.det.nsw.edu.au"))
        return "DIRECT";


	// Revised schools version
	// Created 2014-05-02

	// Go Direct for NetBios and localhosts
	if (isPlainHostName(host) ||
		localHostOrDomainIs(host, "localhost") ||
		localHostOrDomainIs(host, "127.0.0.1"))
	return "DIRECT";

	// Go Direct for local School, TAFE and CPC services
	if (dnsDomainIs (host, ".win") ||
		dnsDomainIs (host, ".schools.nsw.edu.au") ||
		dnsDomainIs (host, ".dlr.det.nsw.edu.au") ||
		dnsDomainIs (host, ".dtmanagement.det.nsw.edu.au") ||
		dnsDomainIs (host, ".cli.det.nsw.edu.au") ||
		dnsDomainIs (host, ".cs.education.nsw.gov.au") ||
		dnsDomainIs (host, ".ps.education.nsw.gov.au") ||
		dnsDomainIs (host, ".ghs.education.nsw.gov.au") ||
		dnsDomainIs (host, ".ssp.education.nsw.gov.au") ||
		dnsDomainIs (host, ".is.education.nsw.gov.au") ||
		dnsDomainIs (host, ".mcc.education.nsw.gov.au") ||
		dnsDomainIs (host, ".sg.education.nsw.gov.au") ||
		dnsDomainIs (host, ".hs.education.nsw.gov.au") ||
		dnsDomainIs (host, ".dec.education.nsw.gov.au") ||
		dnsDomainIs (host, ".bmcc.education.nsw.gov.au") ||
		dnsDomainIs (host, ".eec.education.nsw.gov.au") ||
		dnsDomainIs (host, ".lc.education.nsw.gov.au") ||
		dnsDomainIs (host, ".office.education.nsw.gov.au") ||
		dnsDomainIs (host, ".reg.education.nsw.gov.au") ||
		dnsDomainIs (host, ".sreg.education.nsw.gov.au") ||
		dnsDomainIs (host, ".ssp.education.nsw.gov.au") ||
		localHostOrDomainIs(host, "guzzoni.apple.com") ||
		shExpMatch (url, "*://10.*") ||
		shExpMatch (url, "*://172.16.*") ||
		shExpMatch (url, "*://172.17.*") ||
		shExpMatch (url, "*://172.18.*") ||
		shExpMatch (url, "*://172.19.*") ||
		shExpMatch (url, "*://172.2?.*") ||
		shExpMatch (url, "*://172.30.*") ||
		shExpMatch (url, "*://172.31.*") ||
		shExpMatch (url, "*://153.107.*"))
	return "DIRECT";

        // Go Direct for Portals and SSO
        if (    shExpMatch (host, "sso.*.det.nsw.edu.au") ||
                shExpMatch (host, "saml.*.det.nsw.edu.au") ||
                shExpMatch (host, "portal.*.det.nsw.edu.au") ||
                shExpMatch (host, "staff.*.det.nsw.edu.au") ||
                shExpMatch (host, "student.*.det.nsw.edu.au") ||
                shExpMatch (host, "ssoaddons.*.det.nsw.edu.au") ||
                shExpMatch (host, "ssoaddonsext.*.det.nsw.edu.au") ||
                shExpMatch (host, "extranet.*.det.nsw.edu.au") ||
		shExpMatch (host, "edgeportal.det.nsw.edu.au") ||
                shExpMatch (host, "parent.*.det.nsw.edu.au"))
        return "DIRECT";


	// Send all other request at Proxy
	return "PROXY proxy.det.nsw.edu.au:8080";
}
