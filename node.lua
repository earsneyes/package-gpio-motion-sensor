gl.setup(NATIVE_WIDTH, NATIVE_HEIGHT)

local count = 0

local video = resource.load_video{
    file = "helloworld.mp4";
    looped = false;
}

util.data_mapper{
    counter = function(counter)
        count = counter
end,
}


function node.render()
    video:draw(960, 540, WIDTH, HEIGHT)
    font:write(30,10, "MORE Motion diggha", 100, .5, .5, .5,1)
    countStr = tostring(count)
    font:write(250, 300, countStr, 64, 1,1,1,1)
end
