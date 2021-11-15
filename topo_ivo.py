"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    """Simple topology example."""

    def build( self ):
        """Create custom topo."""

        # Agregamos switches con sus respectivos host
        s1 = self.addSwitch( 's1', protocols='OpenFlow13' )
        
        h1 = self.addHost( 'h1', ip="10.0.0.1/24" )
        h2 = self.addHost( 'h2', ip="10.0.0.2/24" )
        h3 = self.addHost( 'h3', ip="10.0.0.3/24" )
        h4 = self.addHost( 'h4', ip="10.0.0.4/24" )
        
        s2 = self.addSwitch( 's2', protocols='OpenFlow13' )
        
        h5 = self.addHost( 'h5', ip="10.0.0.5/24" )
        h6 = self.addHost( 'h6', ip="10.0.0.6/24" )
        h7 = self.addHost( 'h7', ip="10.0.0.7/24" )
        h8 = self.addHost( 'h8', ip="10.0.0.8/24" )
        
        s3 = self.addSwitch( 's3', protocols='OpenFlow13' )
        
        h9 = self.addHost( 'h9', ip="10.0.0.9/24" )
        h10 = self.addHost( 'h10', ip="10.0.0.10/24" )
        h11 = self.addHost( 'h11', ip="10.0.0.11/24" )
        h12 = self.addHost( 'h12', ip="10.0.0.12/24" )
        
        s4 = self.addSwitch( 's4', protocols='OpenFlow13' )
       
        h13 = self.addHost( 'h13', ip="10.0.0.13/24" )
        h14 = self.addHost( 'h14', ip="10.0.0.14/24" )
        h15 = self.addHost( 'h15', ip="10.0.0.15/24" )
        h16 = self.addHost( 'h16', ip="10.0.0.16/24" )
        # Add links
        
        # Primer switch
        self.addLink (h1,s1)
        self.addLink (h2,s1)
        self.addLink (h3,s1)
        self.addLink (h4,s1)
        
        #segundo switch
	self.addLink (h5,s2)
	self.addLink (h6,s2)
	self.addLink (h7,s2)
	self.addLink (h8,s2)
	
	#tercer switch
	self.addLink (h9,s3)
	self.addLink (h10,s3)
	self.addLink (h11,s3)
	self.addLink (h12,s3)
	
	#cuarto swich
	
	self.addLink (h13,s4)
	self.addLink (h14,s4)
	self.addLink (h15,s4)
	self.addLink (h16,s4)
	#entre switches
	self.addLink (s1,s2)
	self.addLink (s2,s3)
	self.addLink (s3,s4)
	
topos = { 'mytopo': ( lambda: MyTopo() ) }
