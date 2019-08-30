gl.setup(NATIVE_WIDTH, NATIVE_HEIGHT)

local video = resource.load_video{

    file = "helloworld.mp4";
    looped = false;
}

function node.render()
    video:draw(0, 0, WIDTH, HEIGHT)
end
