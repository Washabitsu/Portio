# Build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first: this layer is reused until the package list changes
COPY Portio/Portio/Portio.csproj Portio/Portio/
RUN dotnet restore Portio/Portio/Portio.csproj

COPY Portio/Portio/ Portio/Portio/
RUN dotnet publish Portio/Portio/Portio.csproj -c Release -o /app/publish --no-restore

# Run
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .

# Folder for the Data Protection keys (a volume is mounted here). Created now so the non-root user owns it
RUN mkdir /keys && chown $APP_UID /keys

# 8080 is plain HTTP (only redirects to HTTPS). For HTTPS set ASPNETCORE_HTTPS_PORTS=8443 and give Kestrel
# a certificate (ASPNETCORE_Kestrel__Certificates__Default__Path / __Password), as docker-compose.yml does
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080 8443

# The non-root user that the .NET images ship with
USER $APP_UID

ENTRYPOINT ["dotnet", "Portio.dll"]
