public interface IPluginManager
{
    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);
}

public interface IPluginRegistry
{
    Task<IReadOnlyCollection<IPluginContainer>> LoadAsync(IReadOnlyCollection<IPluginMetadata> pluginMetadatas, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<IPluginMetadata>> GetValidPluginVersions(CancellationToken cancellationToken);
}

public interface IPluginContainerStorage
{
    Task<IReadOnlyCollection<IPluginMetadata>> GetPluginsAsync(CancellationToken cancellationToken);

    Task AddPluginsAsync(IReadOnlyCollection<IPluginContainer> pluginContainers, CancellationToken cancellationToken);

    Task<IPluginContainer> GetPluginContainerAsync(IPluginMetadata plugin, CancellationToken cancellationToken);

    Task<IPluginContainer> RemovePluginContainerAsync(IPluginMetadata plugin, CancellationToken cancellationToken);
}

public interface IPluginFactory
{
    IPlugin Create(IPluginMetadata pluginMetadata);
}

public interface IPlugin : IPluginMetadata
{
    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);
}

public interface IPluginContainer : IPluginMetadata
{
    byte[] Data { get; }
}

public interface IPluginMetadata
{
    Version Version { get; }

    string Name { get; }
}

Напиши реализацию IPluginManager, он должен получить список валидных плагинов, если каких то плагинов нет в хранилище, то загрузить их в хранилище, так же он должен хранить мапу запущенных плагинов и в случае чего останавливать плагин, если его версия изменилась. И запускать актуальный