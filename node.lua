gl.setup(NATIVE_WIDTH, NATIVE_HEIGHT)

local font = resource.load_font "font.ttf"
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
    gl.clear(0,0,0,1)
    video:draw(0, 0, WIDTH, HEIGHT)
end
