using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sutra.Cli.Models;

namespace Sutra.Cli.Storage;

public sealed class SqliteHistoryStore
{
    private readonly string _databasePath;
    private readonly string _connectionString;

    public SqliteHistoryStore(string databasePath)
    {
        _databasePath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate
        }.ToString();
        Initialize();
    }

    public static string DefaultDatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sutra", "sutra.db");

    public string DatabasePath => _databasePath;

    public SnapshotSaveResult SaveSnapshot(IReadOnlyList<PipeEndpoint> endpoints)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        var previous = ReadLatestSnapshot(connection, transaction);
        var previousEndpoints = previous is null
            ? new Dictionary<string, (string Fingerprint, string Json)>(StringComparer.OrdinalIgnoreCase)
            : ReadEndpoints(connection, transaction, previous.Id);

        var id = Guid.NewGuid().ToString("D");
        var captured = DateTimeOffset.UtcNow;
        using (var insertSnapshot = connection.CreateCommand())
        {
            insertSnapshot.Transaction = transaction;
            insertSnapshot.CommandText = "INSERT INTO Snapshots (Id, CapturedUtc, EndpointCount) VALUES ($id, $utc, $count)";
            insertSnapshot.Parameters.AddWithValue("$id", id);
            insertSnapshot.Parameters.AddWithValue("$utc", captured.UtcDateTime.ToString("O"));
            insertSnapshot.Parameters.AddWithValue("$count", endpoints.Count);
            insertSnapshot.ExecuteNonQuery();
        }

        var changes = Compare(previousEndpoints, endpoints);
        using (var insertEndpoint = connection.CreateCommand())
        {
            insertEndpoint.Transaction = transaction;
            insertEndpoint.CommandText = "INSERT INTO SnapshotEndpoints (SnapshotId, Name, Fingerprint, EndpointJson) VALUES ($snapshot, $name, $fingerprint, $json)";
            var snapshotParameter = insertEndpoint.Parameters.Add("$snapshot", SqliteType.Text);
            var nameParameter = insertEndpoint.Parameters.Add("$name", SqliteType.Text);
            var fingerprintParameter = insertEndpoint.Parameters.Add("$fingerprint", SqliteType.Text);
            var jsonParameter = insertEndpoint.Parameters.Add("$json", SqliteType.Text);
            foreach (var endpoint in endpoints)
            {
                var json = JsonSerializer.Serialize(endpoint);
                snapshotParameter.Value = id;
                nameParameter.Value = endpoint.Name;
                fingerprintParameter.Value = Fingerprint(json);
                jsonParameter.Value = json;
                insertEndpoint.ExecuteNonQuery();
            }
        }

        transaction.Commit();
        return new SnapshotSaveResult(new ScanSnapshot(id, captured, endpoints.Count), changes);
    }

    public IReadOnlyList<ScanSnapshot> GetRecentSnapshots(int limit = 20)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, CapturedUtc, EndpointCount FROM Snapshots ORDER BY CapturedUtc DESC, rowid DESC LIMIT $limit";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 200));
        using var reader = command.ExecuteReader();
        var snapshots = new List<ScanSnapshot>();
        while (reader.Read())
            snapshots.Add(new ScanSnapshot(reader.GetString(0), DateTimeOffset.Parse(reader.GetString(1)), reader.GetInt32(2)));
        return snapshots;
    }

    public IReadOnlyList<EndpointChange>? GetLatestChanges()
    {
        using var connection = Open();
        var snapshots = GetLatestTwo(connection);
        if (snapshots.Count < 2) return null;
        var previous = ReadEndpoints(connection, null, snapshots[1].Id);
        var current = ReadEndpoints(connection, null, snapshots[0].Id);
        var changes = new List<EndpointChange>();
        foreach (var item in current)
        {
            if (!previous.TryGetValue(item.Key, out var old)) changes.Add(new EndpointChange(EndpointChangeKind.Added, item.Key));
            else if (!StringComparer.Ordinal.Equals(old.Fingerprint, item.Value.Fingerprint)) changes.Add(new EndpointChange(EndpointChangeKind.Modified, item.Key));
        }
        foreach (var item in previous)
            if (!current.ContainsKey(item.Key)) changes.Add(new EndpointChange(EndpointChangeKind.Removed, item.Key));
        return changes.OrderBy(change => change.EndpointName, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public int SaveEvents(IReadOnlyList<SysmonPipeEvent> events)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO SysmonEvents (Channel, RecordId, EventId, TimeUtc, ProcessId, ProcessName, PipeName, EventType, IsCorrelated)
            VALUES ($channel, $recordId, $eventId, $time, $pid, $processName, $pipeName, $eventType, $correlated)
            ON CONFLICT (Channel, RecordId) DO NOTHING
            """;
        var channel = command.Parameters.Add("$channel", SqliteType.Text);
        var recordId = command.Parameters.Add("$recordId", SqliteType.Integer);
        var eventId = command.Parameters.Add("$eventId", SqliteType.Integer);
        var time = command.Parameters.Add("$time", SqliteType.Text);
        var pid = command.Parameters.Add("$pid", SqliteType.Integer);
        var processName = command.Parameters.Add("$processName", SqliteType.Text);
        var pipeName = command.Parameters.Add("$pipeName", SqliteType.Text);
        var eventType = command.Parameters.Add("$eventType", SqliteType.Text);
        var correlated = command.Parameters.Add("$correlated", SqliteType.Integer);
        var inserted = 0;
        foreach (var item in events)
        {
            channel.Value = item.Channel;
            recordId.Value = item.RecordId;
            eventId.Value = item.EventId;
            time.Value = item.TimeUtc.UtcDateTime.ToString("O");
            pid.Value = item.ProcessId.HasValue ? item.ProcessId.Value : DBNull.Value;
            processName.Value = item.ProcessName is not null ? item.ProcessName : DBNull.Value;
            pipeName.Value = item.PipeName;
            eventType.Value = item.EventType;
            correlated.Value = item.IsCorrelated ? 1 : 0;
            inserted += command.ExecuteNonQuery();
        }
        transaction.Commit();
        return inserted;
    }

    public IReadOnlyList<SysmonPipeEvent> GetRecentEvents(int limit = 50)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Channel, RecordId, EventId, TimeUtc, ProcessId, ProcessName, PipeName, EventType, IsCorrelated FROM SysmonEvents ORDER BY TimeUtc DESC LIMIT $limit";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 500));
        using var reader = command.ExecuteReader();
        var events = new List<SysmonPipeEvent>();
        while (reader.Read())
        {
            events.Add(new SysmonPipeEvent(reader.GetString(0), reader.GetInt64(1), reader.GetInt32(2),
                DateTimeOffset.Parse(reader.GetString(3)), reader.IsDBNull(4) ? null : checked((uint)reader.GetInt64(4)),
                reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetInt32(8) != 0));
        }
        return events;
    }

    private void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS Snapshots (
                Id TEXT PRIMARY KEY,
                CapturedUtc TEXT NOT NULL,
                EndpointCount INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS SnapshotEndpoints (
                SnapshotId TEXT NOT NULL REFERENCES Snapshots(Id) ON DELETE CASCADE,
                Name TEXT NOT NULL COLLATE NOCASE,
                Fingerprint TEXT NOT NULL,
                EndpointJson TEXT NOT NULL,
                PRIMARY KEY (SnapshotId, Name)
            );
            CREATE TABLE IF NOT EXISTS SysmonEvents (
                Channel TEXT NOT NULL,
                RecordId INTEGER NOT NULL,
                EventId INTEGER NOT NULL,
                TimeUtc TEXT NOT NULL,
                ProcessId INTEGER NULL,
                ProcessName TEXT NULL,
                PipeName TEXT NOT NULL,
                EventType TEXT NOT NULL,
                IsCorrelated INTEGER NOT NULL,
                PRIMARY KEY (Channel, RecordId)
            );
            CREATE INDEX IF NOT EXISTS IX_Snapshots_CapturedUtc ON Snapshots(CapturedUtc);
            CREATE INDEX IF NOT EXISTS IX_SysmonEvents_TimeUtc ON SysmonEvents(TimeUtc);
            """;
        command.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private static List<ScanSnapshot> GetLatestTwo(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, CapturedUtc, EndpointCount FROM Snapshots ORDER BY CapturedUtc DESC, rowid DESC LIMIT 2";
        using var reader = command.ExecuteReader();
        var snapshots = new List<ScanSnapshot>();
        while (reader.Read()) snapshots.Add(new ScanSnapshot(reader.GetString(0), DateTimeOffset.Parse(reader.GetString(1)), reader.GetInt32(2)));
        return snapshots;
    }

    private static ScanSnapshot? ReadLatestSnapshot(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT Id, CapturedUtc, EndpointCount FROM Snapshots ORDER BY CapturedUtc DESC, rowid DESC LIMIT 1";
        using var reader = command.ExecuteReader();
        return reader.Read() ? new ScanSnapshot(reader.GetString(0), DateTimeOffset.Parse(reader.GetString(1)), reader.GetInt32(2)) : null;
    }

    private static Dictionary<string, (string Fingerprint, string Json)> ReadEndpoints(SqliteConnection connection, SqliteTransaction? transaction, string snapshotId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT Name, Fingerprint, EndpointJson FROM SnapshotEndpoints WHERE SnapshotId = $id";
        command.Parameters.AddWithValue("$id", snapshotId);
        using var reader = command.ExecuteReader();
        var endpoints = new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read()) endpoints[reader.GetString(0)] = (reader.GetString(1), reader.GetString(2));
        return endpoints;
    }

    private static IReadOnlyList<EndpointChange> Compare(
        IReadOnlyDictionary<string, (string Fingerprint, string Json)> previous,
        IReadOnlyList<PipeEndpoint> current)
    {
        var changes = new List<EndpointChange>();
        var currentNames = new HashSet<string>(current.Select(endpoint => endpoint.Name), StringComparer.OrdinalIgnoreCase);
        foreach (var endpoint in current)
        {
            if (!previous.TryGetValue(endpoint.Name, out var old)) changes.Add(new EndpointChange(EndpointChangeKind.Added, endpoint.Name));
            else if (!StringComparer.Ordinal.Equals(old.Fingerprint, Fingerprint(JsonSerializer.Serialize(endpoint))))
                changes.Add(new EndpointChange(EndpointChangeKind.Modified, endpoint.Name));
        }
        foreach (var endpoint in previous.Keys)
            if (!currentNames.Contains(endpoint)) changes.Add(new EndpointChange(EndpointChangeKind.Removed, endpoint));
        return changes.OrderBy(change => change.EndpointName, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string Fingerprint(string json) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
}
