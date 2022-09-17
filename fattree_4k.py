from mininet.topo import Topo

# Fat tree with k=4
#	4 core switch
#	8 Aggregation switch
#	8 Edge Switch

class MyTopo( Topo ):

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )
        h7 = self.addHost( 'h7' )
        h8 = self.addHost( 'h8' )
        h9 = self.addHost( 'h9' )
        h10 = self.addHost( 'h10' )
        h11 = self.addHost( 'h11' )
        h12 = self.addHost( 'h12' )
        h13 = self.addHost( 'h13' )
        h14 = self.addHost( 'h14' )
        h15 = self.addHost( 'h15' )
        h16 = self.addHost( 'h16' )

        #Pool Client
        h100 = self.addHost( 'h100' )
        h101 = self.addHost( 'h101' )
        h102 = self.addHost( 'h102' )
        h103 = self.addHost( 'h103' )
        h104 = self.addHost( 'h104' )
        h105 = self.addHost( 'h105' )
        h106 = self.addHost( 'h106' )
        h107 = self.addHost( 'h107' )
        h108 = self.addHost( 'h108' )
        h109 = self.addHost( 'h109' )
        h110 = self.addHost( 'h110' )
        h111 = self.addHost( 'h111' )

        # Core switch layer
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        # Swith layer
        s13 = self.addSwitch( 's13' )
        s14 = self.addSwitch( 's14' )
        s15 = self.addSwitch( 's15' )
        s16 = self.addSwitch( 's16' )
        s17 = self.addSwitch( 's17' )
        s18 = self.addSwitch( 's18' )
        s19 = self.addSwitch( 's19' )
        s20 = self.addSwitch( 's20' )

        # Aggregation layer
        s5 = self.addSwitch( 's5' )
        s6 = self.addSwitch( 's6' )
        s7 = self.addSwitch( 's7' )
        s8 = self.addSwitch( 's8' )
        s9 = self.addSwitch( 's9' )
        s10 = self.addSwitch( 's10' )
        s11 = self.addSwitch( 's11' )
        s12 = self.addSwitch( 's12' )


        # POD 1
        self.addLink( h1, s13 )
        self.addLink( h2, s13 )
        self.addLink( h3, s14 )
        self.addLink( h4, s14 )
        self.addLink( s13, s5 )
        self.addLink( s13, s6 )
        self.addLink( s14, s5 )
        self.addLink( s14, s6 )

        # POD 2
        self.addLink( h5, s15 )
        self.addLink( h6, s15 )
        self.addLink( h7, s16 )
        self.addLink( h8, s16 )
        self.addLink( s15, s7 )
        self.addLink( s15, s8 )
        self.addLink( s16, s7 )
        self.addLink( s16, s8 )

        # POD 3
        self.addLink( h9, s17 )
        self.addLink( h10, s17 )
        self.addLink( h11, s18 )
        self.addLink( h12, s18 )
        self.addLink( s17, s9 )
        self.addLink( s17, s10 )
        self.addLink( s18, s9 )
        self.addLink( s18, s10 )

        # POD 4
        self.addLink( h13, s19 )
        self.addLink( h14, s19 )
        self.addLink( h15, s20 )
        self.addLink( h16, s20 )
        self.addLink( s19, s11 )
        self.addLink( s19, s12 )
        self.addLink( s20, s11 )
        self.addLink( s20, s12 )

        # Core Switch 1
        self.addLink( s1, s5 )
        self.addLink( s1, s7 )
        self.addLink( s1, s9 )
        self.addLink( s1, s11 )

        # Core Switch 2
        self.addLink( s2, s5 )
        self.addLink( s2, s7 )
        self.addLink( s2, s9 )
        self.addLink( s2, s11 )

        # Core Switch 3
        self.addLink( s3, s6 )
        self.addLink( s3, s8 )
        self.addLink( s3, s10 )
        self.addLink( s3, s12 )

        # Core Switch 4
        self.addLink( s4, s6 )
        self.addLink( s4, s8 )
        self.addLink( s4, s10 )
        self.addLink( s4, s12 )

        # Clients
        self.addLink( s1, h100 )
        self.addLink( s1, h101 )
        self.addLink( s2, h102 )
        self.addLink( s2, h103 )
        self.addLink( s3, h104 )
        self.addLink( s3, h105 )
        self.addLink( s4, h106 )
        self.addLink( s4, h107 )
        self.addLink( s1, h108 )
        self.addLink( s3, h109 )
        self.addLink( s4, h110 )
        self.addLink( s3, h111 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
