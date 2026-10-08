package webservice

// gamingServices owns the gaming service catalog.
var gamingServices = map[string]KnownService{
	"crafty": {
		Key: "crafty", Name: "Crafty Controller", Category: CatGaming, IconKey: "crafty-controller",
		DefaultPort: 8443, HealthPath: "/",
		DockerImages: []string{"registry.gitlab.com/crafty-controller/crafty-4"},
		Description:  "Minecraft server management panel",
	},
	"pterodactyl": {
		Key: "pterodactyl", Name: "Pterodactyl", Category: CatGaming, IconKey: "pterodactyl",
		DefaultPort: 80, HealthPath: "/",
		DockerImages: []string{"ghcr.io/pterodactyl/panel"},
		Description:  "Game server management panel",
	},
	"pelican": {
		Key: "pelican", Name: "Pelican Panel", Category: CatGaming, IconKey: "pelican-panel",
		DefaultPort: 80, HealthPath: "/",
		DockerImages: []string{"ghcr.io/pelican-dev/panel"},
		Description:  "Game server management panel (Pterodactyl fork)",
	},
	"pufferpanel": {
		Key: "pufferpanel", Name: "PufferPanel", Category: CatGaming, IconKey: "pufferpanel",
		DefaultPort: 8080, HealthPath: "/api/health",
		DockerImages: []string{"pufferpanel/pufferpanel"},
		Description:  "Open-source game server management",
	},
	"amp": {
		Key: "amp", Name: "AMP", Category: CatGaming, IconKey: "amp",
		DefaultPort: 8080, HealthPath: "/",
		DockerImages: []string{"cubecoders/amp"},
		Description:  "Application Management Panel for game servers",
	},
}
