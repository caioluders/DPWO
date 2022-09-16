import importlib
import os, inspect
import importlib.util

def load_plugins():
        plugin_folder = "./plugins"
        possible_plugins = os.listdir(plugin_folder)
        plugins = []
        plugins_instances = []

        for plugin in possible_plugins:
            if plugin.endswith(".py") and plugin != 'PluginLoader.py':
                plugins.append(plugin)

        for p in plugins: 
            location = plugin_folder + '/' + p
            if p[-3:] != '.py' or os.path.isfile(location) != True:
                pass
            spec = importlib.util.spec_from_file_location(p[:-3], location)
            spec_module = spec.loader.load_module()
            members = inspect.getmembers(spec_module, inspect.isclass)
            if members[0][0] != 'PluginInterface': #for some reason, in the 'VIVO' plugin, the first class found is the interface
                class_aux = members[0]
            else:
                class_aux = members[1]
            plugins_instances.append(class_aux[1]())
        return plugins_instances
