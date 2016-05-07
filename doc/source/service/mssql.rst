MSSQL
=====

This module implements the Tabular Data Stream protocol which is used by
Microsoft SQL Server. It listens to tcp/1433 and allows clients to
login. It can decode queries run on the database, but as there is no
database, dionaea can't reply, and there is no further action. Typically
we always get the same query:

.. code-block:: text

    exec sp_server_info 1 exec sp_server_info 2 exec sp_server_info 500 select 501,NULL,1 where 'a'='A' select 504,c.name,c.description,c.definition from master.dbo.syscharsets c,master.dbo.syscharsets c1,master.dbo.sysconfigures f where f.config=123 and f.value=c1.id and c1.csid=c.id set textsize 2147483647 set arithabort on

Refer to the blog
<http://carnivore.it/2010/09/11/mssql_attacks_examined> for more
information.
Patches would be appreciated.

Example config
--------------

.. literalinclude:: ../../../conf/services/mssql.yaml
    :language: yaml
    :caption: services/mssql.yaml
